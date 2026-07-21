# 03. Серверный демон

## 1. Режим работы

`fileshare-daemon` — неинтерактивный процесс:

- stdin не используется (admin-консоль v1 удаляется);
- логирование в stdout/stderr в формате `2026-07-15T12:00:00Z INFO  [session 42] ...` —
  собирается Docker'ом или journald;
- реагирует на сигналы: `SIGTERM`/`SIGINT` → graceful shutdown с дренажом (логика M5),
  `SIGHUP` → перечитать конфиг с диска;
- один процесс, транспорт — epoll + пул потоков (v1 M4), опционально корутины.

```
fileshare-daemon --config /etc/fileshare/config.json
                 [--port N]        # override поверх конфига
                 [--share-root DIR]
                 [--check-config]  # провалидировать конфиг и выйти (для CI/деплоя)
```

## 2. Конфигурация

Один JSON-файл. Каждый параметр помечен: **hot** — применяется на лету,
**restart** — требует перезапуска (таких минимум).

```jsonc
{
  "server": {
    "port": 5555,                  // restart
    "share_root": "/srv/fileshare/share",   // restart (смена корня на лету опасна)
    "workers": 0,                  // restart; 0 = по числу ядер
    "motd": "Добро пожаловать"     // hot
  },
  "limits": {
    "max_connections": 200,        // hot (действует на новые подключения)
    "max_sessions_per_user": 3,    // hot
    "per_client_bps": 0,           // hot; 0 = без лимита
    "global_bps": 0,               // hot
    "handshake_timeout_s": 10,     // hot
    "idle_timeout_s": 600,         // hot; PING/PONG держит сессию живой
    "auth_fail_ban_s": 60          // hot
  },
  "checksum": { "algo": "sha256", "cache_file": "checksums.cache" },  // restart
  "events":   { "enabled": true, "debounce_ms": 500 },               // hot
  "auth":     { "users_file": "/etc/fileshare/users.json" },          // restart (путь), содержимое файла — hot
  "log":      { "level": "info" }                                     // hot
}
```

`users.json` (до перехода на SQLite в M13):

```jsonc
{
  "users": [
    { "login": "admin", "role": "admin",
      "argon2": "$argon2id$v=19$m=65536,t=3,p=1$...", "enabled": true },
    { "login": "vit",   "role": "user",
      "argon2": "$argon2id$...", "enabled": true }
  ]
}
```

Пользователей создаёт утилита `fileshare-daemon --add-user LOGIN --role ROLE`
(спрашивает пароль с терминала, дописывает в users.json) — либо админ-клиент (M11).

## 3. Горячее применение настроек (ключевой механизм)

Требование: «админ поменял лимит скорости — сервер подхватил сразу, без перезапуска».

### 3.1. SettingsHub — снапшоты вместо мьютексов

```cpp
class SettingsHub {
public:
    // Горячий путь: lock-free чтение актуального снапшота.
    std::shared_ptr<const Settings> current() const {
        return std::atomic_load(&snapshot_);      // или atomic<shared_ptr> из C++20
    }
    // Холодный путь: применить изменение (админ-канал, SIGHUP, inotify).
    ApplyResult apply(const Settings& next);      // валидация → swap → persist → EVENT_CONFIG
private:
    std::shared_ptr<const Settings> snapshot_;
};
```

- Рабочие потоки на каждой итерации (перед отправкой очередного чанка, при приёме
  нового соединения) берут `current()` — это одна атомарная загрузка указателя,
  дешевле любого мьютекса, и никогда не блокирует.
- Изменение — copy-on-write: собрать новый `Settings`, свалидировать целиком,
  атомарно подменить. Старый снапшот доживает, пока на него держат ссылки.
- `apply()` после подмены: (1) сериализует конфиг обратно на диск (админ-изменения
  переживают перезапуск), (2) публикует `EVENT_CONFIG` подписчикам, (3) пишет в лог
  «кто, что, с какого значения на какое».

### 3.2. Три источника изменений — одна точка входа

```
ADMIN_SET (сеть) ──┐
SIGHUP            ─┼──► SettingsHub::apply() ──► снапшот · диск · EVENT_CONFIG · лог
inotify(config)   ─┘
```

Конфликт «правили файл руками, пока админ менял по сети» решается просто:
последний `apply()` побеждает, каждое применение логируется с источником.

### 3.3. Какие параметры «hot» и как именно подхватываются

| Параметр | Как подхватывается |
|---|---|
| `per_client_bps`, `global_bps` | RateLimiter читает снапшот на каждом чанке |
| `max_connections` | проверяется в accept-цикле; лишних новых — вежливый `ERROR(RATE_LIMITED)` |
| `idle_timeout_s`, `handshake_timeout_s` | таймер-колесо сверяется со снапшотом |
| `motd`, `log.level` | читаются в момент использования |
| `users.json` | inotify на файл → перезагрузка таблицы пользователей; активные сессии отключённого пользователя рвутся |

## 4. Ограничение скорости (RateLimiter)

Token bucket, два уровня:

- **per-client**: у каждой сессии своё ведро `limits.per_client_bps`;
- **global**: общее ведро на процесс.

Перед отправкой чанка воркер запрашивает `min(CHUNK_SIZE, доступно_в_обоих_вёдрах)`.
Если токенов нет — соединение снимается с `EPOLLOUT` и взводится таймер до момента
пополнения (никаких sleep в воркерах, backpressure остаётся событийным — это
естественно ложится на существующую машину состояний epoll-сервера v1).

Смена лимита на лету = изменение скорости пополнения ведра; ёмкость пересчитывается,
накопленные токены обрезаются по новой ёмкости.

## 5. VFS-слой

Замена плоского `Catalog`:

```cpp
class Vfs {
public:
    explicit Vfs(std::filesystem::path share_root);
    std::vector<DirEntry> list(const std::string& vpath) const;   // с валидацией пути
    std::optional<DirEntry> stat(const std::string& vpath) const;
    Checksum checksum(const std::string& vpath);   // лениво, с кэшем
    std::filesystem::path resolve(const std::string& vpath) const; // realpath + проверка префикса
};
```

- **Валидация пути** — единственная точка (`resolve`): нормализация, запрет `..`,
  realpath-проверка «не вышли ли по симлинку из share_root».
- **Checksum-кэш**: ключ `(vpath, size, mtime)` → checksum; персистится в
  `checksums.cache` (иначе после рестарта пересчитывать гигабайты). Считается в
  фоновом низкоприоритетном потоке при первом запросе; пока не готов —
  `CHECKSUM_RESPONSE` c `algo=0` («ещё считается»), клиент показывает `~`.
- **inotify-наблюдатель** (рекурсивный, с дебаунсом) кормит EventBus и
  инвалидирует checksum-кэш.

## 6. Деплой

### 6.1. Docker (сейчас, локально)

Обновление существующих Dockerfile/docker-compose:

```yaml
services:
  fileshare:
    build: .
    ports: ["5555:5555"]
    volumes:
      - ./data/share:/srv/fileshare/share
      - ./data/etc:/etc/fileshare        # config.json, users.json, checksums.cache
    restart: unless-stopped
    stop_grace_period: 90s               # >= grace дренажа, чтобы docker не убил раньше
```

`STOPSIGNAL SIGTERM` уже соответствует graceful-обработке M5.

### 6.2. systemd (VPS, Timeweb Cloud)

```ini
[Unit]
Description=fileshare daemon
After=network-online.target

[Service]
Type=exec
User=fileshare
ExecStart=/usr/local/bin/fileshare-daemon --config /etc/fileshare/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
TimeoutStopSec=90
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/fileshare /etc/fileshare
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

На VPS вариант ещё проще — тот же docker compose; systemd-юнит нужен, если
захочется без Docker. Рекомендация: **начать с docker compose и на VPS тоже** —
одинаковое окружение локально и в проде, а systemd-юнит держать как альтернативу.

### 6.3. Чек-лист выката на VPS

1. Открыть порт 5555 в файрволе VPS только при необходимости; лучше — держать
   и планировать TLS (см. [06-security.md](06-security.md)).
2. `--check-config` в CI перед рестартом.
3. Логи: `docker logs -f` / `journalctl -u fileshare`.
4. Данные (`share/`, `etc/`) — на отдельном volume, бэкапить `users.json` и конфиг.
