# 09. Перенос проекта на Go — подробное руководство

Этот документ — **самодостаточная спецификация** для переписывания v2-системы
(«FShare Commander», этапы M7–M11) с C++20 на Go. Он рассчитан на то, что вы
(или ИИ-агент) в **отдельном репозитории** реализуете всё с нуля, имея под рукой
только этот файл и, при желании, исходный C++ как справочник.

Цель — не «механический транслит строка-в-строку», а **идиоматичный Go**, который
даёт ровно то же поведение и (важно) **тот же байтовый протокол на проводе**. Если
проволочный формат совпадёт байт-в-байт, Go-сервер сможет обслуживать текущий
C++-клиент и наоборот — это отличный интеграционный тест.

> **Scope.** Переносим M7–M11 (демон, аутентификация, TUI-клиент, live-события,
> админ). M12–M14 (пользователи/квоты, upload, TLS) — перспектива, здесь не
> реализуются, но модель данных под них закладывается так же, как в C++.

Содержание:
1. [Что переносим (обзор системы)](#1-что-переносим)
2. [Почему Go проще: где язык даёт выигрыш](#2-где-go-даёт-выигрыш)
3. [Структура Go-модуля (пакеты)](#3-структура-go-модуля)
4. [Проволочный протокол — точная спецификация](#4-проволочный-протокол)
5. [Пакет за пакетом: как портировать](#5-пакет-за-пакетом)
6. [Модель конкурентности: C++ → Go](#6-модель-конкурентности)
7. [Безопасность: критичные детали](#7-безопасность)
8. [Чек-лист уже найденных багов (не переизобретать)](#8-чек-лист-багов)
9. [Тестирование и порядок работ](#9-тестирование-и-порядок-работ)
10. [Сборка, деплой, Docker в Go](#10-сборка-и-деплой)
11. [Рекомендации по библиотекам](#11-библиотеки)
12. [Приложения: таблицы констант и схемы файлов](#12-приложения)

---

## 1. Что переносим

Три артефакта (в C++ — `fileshare-daemon`, `fileshare-commander`, ядро
`fileshare_v2_core`; в Go — три `main`-пакета + библиотечные пакеты):

- **Демон** — неинтерактивный сервер. Раздаёт **дерево директорий** (VFS над
  `share_root`), аутентификация challenge–response (пароль не ходит по сети),
  **push-события** об изменениях файлов (inotify → `EVENT_FS`), **живое
  управление без перезапуска** (лимит скорости и пр. применяются на лету),
  graceful shutdown, reload по `SIGHUP`.
- **TUI-клиент** — полноэкранный командер в стиле Midnight Commander: две панели,
  горячие клавиши, скачивание с прогрессом/докачкой, подсветка нового,
  индикатор связи + авто-реконнект, админ-панель по F9. Плюс `--batch` для
  скриптов.
- **Ядро** — протокол v2, VFS, crypto/auth, сессии, rate limiter, settings hub,
  наблюдатель ФС, сервер, клиент.

Объём C++ v2 — ~6.4k строк (заголовки+исходники) + ~10 тестовых файлов. На Go
ожидается заметно меньше за счёт stdlib (`net`, `encoding/binary`, `crypto/*`,
`os.Root`, `context`) и Bubble Tea.

Исходное соответствие C++-файлов и назначения — в разделе [5](#5-пакет-за-пакетом).

---

## 2. Где Go даёт выигрыш

Отметьте это заранее — часть ручной работы в C++ в Go «исчезает»:

| C++-задача | В Go |
|---|---|
| `openat2(RESOLVE_BENEATH)` вручную через `syscall`, fallback для не-Linux | **`os.Root`** (Go 1.24+): `root, _ := os.OpenRoot(shareRoot); f, err := root.Open(vpath)` — встроенное удержание внутри корня, кроссплатформенно. Убирает весь `vfs`-хардкор с symlink-escape |
| Свой SHA-256 (чтобы работать без OpenSSL) | `crypto/sha256`, `crypto/hmac`, `golang.org/x/crypto/pbkdf2` — из коробки |
| `atomic<shared_ptr<const Settings>>` для горячего конфига | **`atomic.Pointer[Settings]`** (Go 1.19+) — снапшоты один-в-один |
| Token bucket вручную | `golang.org/x/time/rate` (`Limiter.WaitN`) |
| inotify через сырой `syscall`, рекурсивные вотчи, `IN_IGNORED` | **`github.com/fsnotify/fsnotify`** — кроссплатформенно (inotify/kqueue/ReadDirectoryChangesW) |
| Поток-на-соединение + ручной join, condvar-дренаж | горутина-на-соединение + `context.Context` + `sync.WaitGroup`. GC убирает use-after-free |
| Per-session send-mutex + `try_lock` для событий | **исходящий канал на сессию** + одна писательская горутина → медленный клиент **не** тормозит остальных (закрывает известное ограничение C++, см. §8) |
| FTXUI + ручной цикл событий, отдельный поток сети | **Bubble Tea** (Elm-архитектура). Ваши `AppState`/`Command`/`Result` из C++ = `Model`/`Cmd`/`Msg` в Bubble Tea почти дословно |
| Кроссплатформенная сборка через Docker multi-stage | `GOOS=linux GOARCH=amd64 go build` → один статический бинарь. Docker становится `FROM scratch` + бинарь |

**Вывод:** архитектура C++ (разделение «что делает сервер» и «как двигаются
байты», `Command/Result`, снапшоты конфига) переносится в Go почти дословно, а
самые муторные куски (openat2, свой crypto, свой inotify, свой token bucket)
заменяются на stdlib/x-пакеты.

---

## 3. Структура Go-модуля

Идиоматичная раскладка (`module github.com/<you>/fshare`):

```
cmd/
  fshare-daemon/main.go        // был daemon_main.cpp
  fshare-commander/main.go     // был commander_main.cpp
internal/
  proto/                       // был protocol.hpp/cpp + wire.hpp/cpp
    proto.go                   //   константы, коды, кодеры/парсеры
    frame.go                   //   фрейминг (заголовок 5 байт) + read/write через io.Reader/Writer
    messages.go                //   структуры сообщений
  vfs/                         // был vfs.hpp/cpp — теперь тонкая обёртка над os.Root
    vfs.go
  auth/                        // был crypto.* + auth.*
    scram.go                   //   challenge-response (PBKDF2/HMAC/SHA-256/subtle)
    userdb.go                  //   users.json
    guard.go                   //   AuthGuard (бан по IP)
  config/                      // был settings.* + settings_hub.*
    settings.go
    hub.go                     //   atomic.Pointer снапшоты
  server/                      // был server.*, server_context.*, session.*, dispatch.*
    server.go                  //   accept-loop, graceful shutdown
    conn.go                    //   обработка одного соединения (handshake + loop)
    session.go                 //   Session + Registry
    dispatch.go                //   таблица min-role
    context.go                 //   ServerContext (VFS+config+sessions+limiter+stats)
    admin.go                   //   ADMIN_* хендлеры
  ratelimit/                   // был rate_limiter.*
    ratelimit.go
  watcher/                     // был fs_watcher.* — теперь обёртка над fsnotify
    watcher.go
  client/                      // был client.hpp/cpp
    client.go
  tui/                         // был tui/model.*, view.*, connection.*
    model.go                   //   Bubble Tea Model (= AppState)
    update.go                  //   Update(msg) (= обработка клавиш + Result)
    view.go                    //   View() (= render_commander/render_admin)
    admin.go                   //   админ-панель
    conn.go                    //   мост клиент→Bubble Tea (Cmd/Msg)
    profiles.go                //   ~/.config/fileshare/profiles.json
go.mod
```

Правило Go: приватные пакеты — под `internal/`, публичные точки входа — под
`cmd/`. Никаких «библиотечных заголовков» — экспортируется то, что с большой
буквы.

---

## 4. Проволочный протокол

Это самая важная часть: реализуйте её **байт-в-байт**, тогда Go и C++ совместимы.

### 4.1. Фрейминг

Каждое сообщение — **заголовок 5 байт + payload**:

```
┌────────┬───────────────────────────┬───────────┐
│msg_type│ payload_length (u32, BE)  │  payload  │
│ 1 байт │        4 байта            │  N байт   │
└────────┴───────────────────────────┴───────────┘
```

- Все числа — **big-endian**. В Go: `encoding/binary.BigEndian`.
- `payload_length` — длина только payload (без заголовка).
- Приём: прочитать 5 байт заголовка (`io.ReadFull`); если 0 байт на границе кадра
  — чистое закрытие. Проверить, что `msg_type` известен и `payload_length ≤
  MAX_CONTROL_PAYLOAD` (4 MiB). Затем `io.ReadFull` на `payload_length` байт.
- Любой некорректный ввод (неизвестный тип, oversize, усечение) → ошибка, которая
  **рвёт только это соединение**, не роняя сервер. В Go — верните `error`,
  вызывающий закрывает conn.

Пример чтения кадра (набросок):

```go
func ReadFrame(r io.Reader) (Msg, []byte, error) {
    var hdr [5]byte
    if _, err := io.ReadFull(r, hdr[:]); err != nil {
        return 0, nil, err // io.EOF на границе = чистое закрытие
    }
    typ := Msg(hdr[0])
    n := binary.BigEndian.Uint32(hdr[1:5])
    if !typ.Known() {
        return 0, nil, fmt.Errorf("unknown msg type 0x%02x", hdr[0])
    }
    if n > MaxControlPayload {
        return 0, nil, fmt.Errorf("payload %d exceeds max", n)
    }
    p := make([]byte, n)
    if _, err := io.ReadFull(r, p); err != nil {
        return 0, nil, err
    }
    return typ, p, nil
}
```

### 4.2. Примитивы сериализации

| Тип | Формат на проводе |
|---|---|
| `u8`/`u16`/`u32`/`u64` | big-endian |
| строка (`str`) | `u16` длина + UTF-8 байты. Лимиты: имя ≤ 255, путь ≤ 4096, обычная строка ≤ 65535 |
| `checksum` | **ровно 32 байта** (SHA-256 занимает все; CRC32 — первые 4, остальное нули) |
| `challenge` | 16 байт |
| `proof` | 32 байта |

`ADMIN_CONFIG` (JSON) использует `u32`-префикс длины (может быть > 64 KiB) —
единственное исключение из «строка = u16».

### 4.3. Константы (точные значения — воспроизвести)

```
PROTO_VERSION        = 2
MAX_PATH_LEN         = 4096
MAX_NAME_LEN         = 255
MAX_STRING_LEN       = 65536      (64 KiB)
MAX_CONTROL_PAYLOAD  = 4194304    (4 MiB)
CHUNK_SIZE           = 65536      (64 KiB)   // размер чанка при стриминге файла
CHALLENGE_LEN        = 16
PROOF_LEN            = 32
CHECKSUM_LEN         = 32
MAX_LIST_ENTRIES     = 1048576    (1<<20)    // потолок числа записей в листинге
HEADER_SIZE          = 5

auth_mode:  NONE=0, CHALLENGE=1
algo:       PENDING=0, CRC32=1, SHA256=2
role:       ANONYMOUS=0, USER=1, ADMIN=2
kind:       FILE=0, DIR=1
fs op:      CREATED=1, MODIFIED=2, REMOVED=3
severity:   INFO=0, WARN=1, ERROR=2
SUBSCRIBE mask bits: FS=1, NOTICE=2, CONFIG=4
DirEntry flags: NEW=1 (bit0)
```

### 4.4. Таблица сообщений (коды и payload)

Коды v1 (0x01–0x05) **не переиспользуются** (дешёвая страховка от путаницы).

| Сообщение | Код | Напр. | Payload |
|---|---|---|---|
| `ERROR` | `0x06` | обе | `code:u16`, `message:str` |
| `PING` | `0x07` | C→S | пусто |
| `PONG` | `0x08` | S→C | пусто |
| `HELLO` | `0x10` | C→S | `proto_ver:u16`, `client_name:str` |
| `HELLO_OK` | `0x11` | S→C | `proto_ver:u16`, `server_name:str`, `auth_mode:u8`, `challenge:16`, `pbkdf2_iters:u32` |
| `AUTH_REQUEST` | `0x12` | C→S | `login:str`, `proof:32` |
| `AUTH_OK` | `0x13` | S→C | `role:u8`, `session_id:u64`, `motd:str` |
| `AUTH_FAIL` | `0x14` | S→C | `reason:u16`, `message:str` |
| `LIST_DIR_REQUEST` | `0x20` | C→S | `path:str` |
| `LIST_DIR_RESPONSE` | `0x21` | S→C | `path:str`, `count:u32`, затем `count`×`DirEntry` |
| `STAT_REQUEST` | `0x22` | C→S | `path:str` |
| `STAT_RESPONSE` | `0x23` | S→C | `path:str`, `DirEntry` |
| `CHECKSUM_REQUEST` | `0x24` | C→S | `path:str` |
| `CHECKSUM_RESPONSE` | `0x25` | S→C | `path:str`, `algo:u8`, `checksum:32` |
| `DOWNLOAD_REQUEST` | `0x30` | C→S | `path:str`, `offset:u64` |
| `DOWNLOAD_ACCEPT` | `0x31` | S→C | `transfer_id:u32`, `total_size:u64` |
| `CHUNK_DATA` | `0x32` | S→C | `transfer_id:u32`, затем сырые байты (≤ CHUNK_SIZE) |
| `DOWNLOAD_DONE` | `0x33` | S→C | `transfer_id:u32`, `algo:u8`, `checksum:32` |
| `DOWNLOAD_CANCEL` | `0x34` | C→S | `transfer_id:u32` |
| `SUBSCRIBE` | `0x40` | C→S | `mask:u32` |
| `EVENT_FS` | `0x41` | S→C | `op:u8`, `kind:u8`, `path:str`, `size:u64`, `mtime:u64` |
| `EVENT_NOTICE` | `0x42` | S→C | `severity:u8`, `text:str` |
| `EVENT_CONFIG` | `0x43` | S→C | `key:str`, `new_value:str` |
| `ADMIN_GET_CONFIG` | `0x50` | C→S | пусто |
| `ADMIN_CONFIG` | `0x51` | S→C | `json_len:u32`, `json:bytes` |
| `ADMIN_SET` | `0x52` | C→S | `key:str`, `value:str` |
| `ADMIN_SET_RESULT` | `0x53` | S→C | `ok:u8`, `message:str` |
| `ADMIN_LIST_CLIENTS` | `0x54` | C→S | пусто |
| `ADMIN_CLIENTS` | `0x55` | S→C | `count:u32`, затем на каждого: `session_id:u64`, `login:str`, `ip:str`, `role:u8`, `current_path:str`, `bytes_sent:u64`, `speed_bps:u64` |
| `ADMIN_KICK` | `0x56` | C→S | `session_id:u64` |
| `ADMIN_KICK_RESULT` | `0x57` | S→C | `ok:u8`, `message:str` |
| `ADMIN_STATS` | `0x58` | C→S | пусто |
| `ADMIN_STATS_RESPONSE` | `0x59` | S→C | `uptime_s:u64`, `bytes_sent:u64`, `completed:u64`, `active_conns:u64`, `active_downloads:u64`, `shared_files:u64`, `per_client_bps:u64`, `global_bps:u64`, `version:str` |
| `ADMIN_SHUTDOWN` | `0x5A` | C→S | `grace_seconds:u32` |
| `ADMIN_SHUTDOWN_RESULT` | `0x5B` | S→C | `ok:u8`, `message:str` |

`DirEntry` на проводе: `name:str` (≤255), `kind:u8`, `size:u64`, `mtime:u64`
(unix-секунды), `flags:u8`.

### 4.5. Порядок кадров (сценарии)

**Рукопожатие:** `HELLO` → `HELLO_OK` → `AUTH_REQUEST` → `AUTH_OK`|`AUTH_FAIL`.
До `AUTH_OK` соединение принимает только `HELLO`/`AUTH_REQUEST`/`PING`. Таймаут
рукопожатия — `limits.handshake_timeout_s`. Первый кадр не-`HELLO` (например,
байт v1) → `ERROR(UNSUPPORTED_VERSION)` и закрытие.

**Скачивание:** `DOWNLOAD_REQUEST` → `DOWNLOAD_ACCEPT` → N×`CHUNK_DATA` →
`DOWNLOAD_DONE`. `offset>0` — докачка (сервер шлёт контрольную сумму **всего**
файла, клиент сверяет собранный файл).

**Ключевая тонкость (не пропустить):** сервер **push-ит** `EVENT_*`/`PONG` в
любой момент, в т.ч. **между запросом и ответом и посреди потока чанков**.
Значит клиент, ожидая конкретный ответ, обязан в цикле пропускать асинхронные
кадры (`EVENT_FS/EVENT_NOTICE/EVENT_CONFIG/PONG`) в обработчик событий и ждать
дальше. То же в цикле скачивания. См. §5 (client) и §8.

---

## 5. Пакет за пакетом

Для каждого — что делал C++, какие Go-типы, идиомы и подводные камни.

### 5.1. `proto` (был `protocol.*`, `wire.*`)

- Определите `type Msg uint8` с константами кодов (§4.4) и `func (Msg) Known() bool`.
- Структуры сообщений (`Hello`, `HelloOk`, `AuthRequest`, `DirEntry`,
  `ListDirResponse`, `DownloadAccept`, `EventFs`, `AdminStats`, …).
- Кодеры возвращают полный кадр (`[]byte`), парсеры принимают payload и
  возвращают `(struct, error)`. Идиома: используйте `bytes.Buffer`/
  `binary.Write` для записи и курсор по срезу для чтения. Заведите
  bounds-checked reader (аналог `ByteReader`): методы `u8/u16/u32/u64/str(max)/
  bytes(n)` возвращают `error` на underflow. **Никаких паник** — только `error`.
- Строгая проверка «нет лишних байт»: после парса payload курсор должен быть в
  конце, иначе — ошибка (как `require_end` в C++). Это ловит несоответствия
  формата.
- Потолки при парсе `LIST_DIR_RESPONSE`/`ADMIN_CLIENTS`: `count` сверять с
  `MAX_LIST_ENTRIES` **до** аллокаций (защита от OOM на враждебном count). Не
  делайте `make([]T, count)` на непроверенном count.
- Тесты: round-trip каждого сообщения + отказ на усечённом/oversize/битом вводе
  (перенести `test_v2_protocol.cpp`).

### 5.2. `vfs` (был `vfs.*`) — сильно упрощается

C++ вручную делал `openat2(RESOLVE_BENEATH)` + нормализацию путей + запрет `..` +
realpath. **В Go всё это = `os.Root`:**

```go
type VFS struct {
    root *os.Root                 // os.OpenRoot(shareRoot)
    cache sync.Map                // checksum-кэш: vpath -> cacheEntry
}
```

- `os.Root.Open`/`Stat`/`OpenFile` держат операции **внутри корня** — символические
  ссылки наружу и `..` не выводят за пределы (Go 1.24+ через `openat2`/
  эмуляцию). Это заменяет весь код `resolve()`/`open_beneath()`.
- Нормализация vpath всё равно нужна для *отображения* (сведение `//`, `.`,
  ведущий `/`), но безопасность даёт `os.Root`. Приведите vpath к относительному
  (`strings.TrimPrefix(clean, "/")`, `"/"` → `"."`) и передавайте в `root.Open`.
- `List(vpath)`: `root.OpenRoot(sub)` + `ReadDir`; сортировка «каталоги сначала,
  затем по имени»; отфильтровать escape-симлинки не нужно — `os.Root` уже
  защищает, но всё же скрывайте записи, которые не открываются внутри корня.
- Ленивый **checksum-кэш** по ключу `(vpath, size, mtime)`; персист в
  `checksums.cache` (JSON). Хеш файла читайте **через `root.Open`** (не по строке
  пути) — тогда TOCTOU закрыт автоматически.
- `mtime` — unix-секунды из `FileInfo.ModTime().Unix()`.
- Ошибки маппьте в `proto.ErrCode`: нет файла → `FILE_NOT_FOUND`, не каталог →
  `NOT_A_DIRECTORY`, каталог вместо файла → `IS_A_DIRECTORY`, выход за корень →
  `ACCESS_DENIED`, кривой путь → `BAD_REQUEST`.

> Если целевой Go < 1.24 (нет `os.Root`), возьмите
> `github.com/cyphar/filepath-securejoin` (тот же `openat2`-подход) — но
> предпочтительно Go 1.24+.

### 5.3. `auth` (был `crypto.*`, `auth.*`)

Схема SCRAM-подобная (пароль по сети не ходит, кража `users.json` не даёт войти).
**Точные параметры — воспроизвести:**

```
salt          = "fileshare-v2:" + login          // детерминированный salt по логину
iters         = 200000 (по умолч.; сервер объявляет в HELLO_OK.pbkdf2_iters)
SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, dkLen=32)
ClientKey     = HMAC-SHA256(SaltedPassword, "Client Key")
StoredKey     = SHA256(ClientKey)                // хранится в users.json (hex)
AuthMessage   = challenge(16 байт) || login(байты)
ClientProof   = ClientKey XOR HMAC-SHA256(StoredKey, AuthMessage)   // 32 байта, идёт в AUTH_REQUEST
```

Сервер проверяет: `recovered = ClientProof XOR HMAC(StoredKey, AuthMessage)`,
затем `SHA256(recovered) == StoredKey` (**constant-time**, `crypto/subtle`).

Go:

```go
import ("crypto/hmac"; "crypto/sha256"; "crypto/subtle"; "golang.org/x/crypto/pbkdf2")

func clientKey(pw, login string, iters int) [32]byte {
    salt := []byte("fileshare-v2:" + login)
    sp := pbkdf2.Key([]byte(pw), salt, iters, 32, sha256.New)
    m := hmac.New(sha256.New, sp); m.Write([]byte("Client Key"))
    var out [32]byte; copy(out[:], m.Sum(nil)); return out
}
```

- `subtle.ConstantTimeCompare(check[:], stored[:]) == 1`.
- Случайные байты (challenge, salt) — `crypto/rand`.
- **UserDb** (`users.json`): `{ "users": [ {login, role, stored_key(hex), enabled} ] }`.
  Отсутствующий файл → пустая БД → **no-auth bootstrap** (все входят как ADMIN).
  Есть пользователи → требуется challenge-auth.
- **AuthGuard**: бан по IP после N (3) неудач на `auth_fail_ban_s`. В Go —
  `map[string]struct{fails int; banUntil time.Time}` под `sync.Mutex`; время
  передавайте (или используйте `time.Now`) — так же, как в C++ (детерминированный
  юнит-тест).
- Тесты: known-answer векторы SHA-256/HMAC/PBKDF2 (RFC 4231 / RFC 7914),
  round-trip challenge-response, отказ на неверном пароле/replay/выключенном
  пользователе. В тестах используйте **малый iters** (например 2048), иначе
  200000 итераций замедлят прогон; сам протокол объявляет iters в `HELLO_OK`.

> Замечание: в C++ был свой SHA-256 (чтобы работать без OpenSSL). В Go не нужно —
> `crypto/sha256` встроен. Argon2id (perspective) — `golang.org/x/crypto/argon2`,
> но по умолчанию оставьте PBKDF2, чтобы формат `stored_key` совпадал.

### 5.4. `config` (был `settings.*`, `settings_hub.*`)

- `Settings` — обычная структура с JSON-тегами (см. схему в §12). Загрузка:
  отсутствующий файл → значения по умолчанию (не ошибка). `Validate()` возвращает
  строку-ошибку или "".
- **`SettingsHub`** — горячий конфиг через снапшоты:

```go
type Hub struct {
    snap atomic.Pointer[Settings]   // hot-path чтение: hub.Current() = hub.snap.Load()
    wmu  sync.Mutex                 // сериализует писателей (Set/Apply)
    onChange func(key, value string)
}
func (h *Hub) Current() *Settings { return h.snap.Load() }
```

- `Set(key, value)`: под `wmu` — скопировать текущий снапшот, распарсить и
  применить значение, `Validate()`, атомарно `snap.Store(&next)`, вызвать
  `onChange`. **Белый список hot-ключей** (см. §12); restart-ключи (`server.port`,
  `server.share_root`) отклонять.
  - ⚠ **Баг из C++, не повторить:** числовые ключи с сужением диапазона — сначала
    проверьте, что значение влезает в целевой тип, **до** присваивания (иначе
    huge-значение молча заворачивается и проходит валидацию). В Go парсите в
    `uint64`, для u32-полей — если `> math.MaxUint32` → ошибка.
- `Apply(next)` (для SIGHUP): **тоже под `wmu`** (это был реальный баг C++:
  `apply` без мьютекса гонялся с `Set`). В Go — просто возьмите `h.wmu`.
- `onChange` (задаётся сервером): персист конфига (**атомарно**: `os.CreateTemp`
  → запись → `os.Rename`) + broadcast `EVENT_CONFIG` подписчикам `SUB_CONFIG`.
  Персист под тем же `wmu`, что и `Set`, чтобы записанный файл и broadcast
  соответствовали одному снапшоту.

### 5.5. `server` (был `server.*`, `server_context.*`, `session.*`, `dispatch.*`)

**ServerContext** — общее состояние: VFS, Hub, реестр сессий, rate limiter,
статистика (atomics: `bytesSent`, `completed`), время старта, `nextTransferID`
(atomic), флаг reload.

**Session** и **Registry:**

```go
type Session struct {
    id      uint64
    ip      string
    login   string   // под mu (ставится при auth)
    role    Role
    subMask atomic.Uint32
    bytes   atomic.Uint64
    curPath atomic.Pointer[string]   // "" когда простаивает

    out     chan []byte  // ИСХОДЯЩИЕ кадры — писатель-горутина сериализует их
    done    chan struct{}
    mu      sync.Mutex
}
```

> **Идиоматичный Go, лучше C++:** вместо per-session mutex + `try_lock` заведите
> **исходящий канал `out`** и одну **писательскую горутину** на соединение,
> которая читает `out` и пишет в сокет. Тогда:
> - `EVENT_FS` broadcast — просто `select { case s.out <- frame: default: /* drop, буфер полон */ }` — **неблокирующая** отправка, медленный клиент **не** тормозит остальных (это закрывает известное ограничение C++ из §8).
> - Кадры атомарны на проводе автоматически (один писатель).
> - Нет гонки «запись в закрытый/переиспользованный fd»: горутина-писатель
>   владеет сокетом единолично; при закрытии соединения она выходит.

**Обработка соединения** (горутина на conn):
1. Зарегистрировать сессию, запустить писательскую горутину (читает `out`).
2. Рукопожатие (см. §4.5) с дедлайнами через `conn.SetReadDeadline`.
   No-auth режим → выдать ADMIN; иначе проверить challenge-proof, учесть бан,
   `max_sessions_per_user`.
3. Цикл запросов: `ReadFrame`; проверка min-role по таблице `dispatch`; хендлер.
   Некорректный кадр → `ERROR(BAD_REQUEST)` и разрыв (только этого соединения).
4. **`defer`** снятия сессии из реестра + закрытие `out`/сокета + `wg.Done()`.

**Таблица ролей (`dispatch`)** — одна функция `MinRole(Msg) Role`:
`HELLO/AUTH_REQUEST/PING/PONG` → ANONYMOUS; FS/transfer/SUBSCRIBE → USER; все
`ADMIN_*` → ADMIN; серверные-only сообщения → ADMIN (клиент не должен их слать).

**Скачивание (хендлер `DOWNLOAD_REQUEST`):**
- Открыть файл **через VFS/`os.Root`**; размер — `Stat`; проверить `offset`.
- Пометить `curPath` (для дренажа/админ-листинга) через **`defer`**-очистку
  (баг C++: при исключении в checksum сессия оставалась «downloading» — в Go
  `defer s.curPath.Store(&empty)` решает).
- Отправить `DOWNLOAD_ACCEPT`, затем цикл: читать чанк, **rate-limit**
  (см. §5.6, читать лимиты из `hub.Current()` **каждый чанк** — тогда изменение
  применяется на лету), отправить `CHUNK_DATA` в `s.out`. Если запись/сокет
  умерли — прервать.
- `DOWNLOAD_DONE` с контрольной суммой всего файла (кэш VFS).

**Admin-хендлеры** (`admin.go`): `ADMIN_GET_CONFIG` (JSON текущего снапшота),
`ADMIN_STATS`, `ADMIN_LIST_CLIENTS`, `ADMIN_KICK` (нельзя себя), `ADMIN_SET`
(через `hub.Set`, с аудит-логом), `ADMIN_SHUTDOWN` (grace). `ADMIN_SET` успех →
`onChange` персистит + broadcast `EVENT_CONFIG`.

**Graceful shutdown:** `context.Context` (отмена по `SIGTERM`/`SIGINT`/
`ADMIN_SHUTDOWN`). Accept-loop выходит по `ctx.Done()`; затем закрыть listener,
дать активным закачкам доиграть (таймаут grace), закрыть остальные соединения,
`wg.Wait()` (аналог `wait_for_handlers`), сохранить checksum-кэш.

> **Баг C++, не повторить:** detached-потоки могли пережить контекст (UAF). В Go
> GC не даёт UAF, но всё равно **дождитесь всех горутин** (`sync.WaitGroup`)
> перед выходом из `Serve()`, чтобы горутины не писали в закрываемые ресурсы.

### 5.6. `ratelimit` (был `rate_limiter.*`)

Token bucket, **per-client** (по логину, не per-transfer!) + глобальный.

- Вариант A (свой, как в C++): `map[string]*bucket` под мьютексом + глобальный
  bucket; `Throttle(clientKey, perClientBps, globalBps, want) int` — сон 5 мс при
  нехватке, возврат гранта. Лимиты читаются **из аргументов каждый вызов** (свежий
  снапшот) → живое изменение.
- Вариант B (идиоматичный Go): `golang.org/x/time/rate`. Держите
  `map[string]*rate.Limiter` (per-client) + один глобальный `*rate.Limiter`;
  `limiter.WaitN(ctx, n)`. При смене лимита — `limiter.SetLimit(newRate)` (можно
  на лету!). Это чище своего sleep-цикла.

> **Баг C++, не повторить:** лимит должен быть **на клиента** (общий bucket для
> всех его параллельных закачек), иначе N соединений = N×лимита. Ключуйте по
> логину. Не забудьте вычищать неактивные bucket'ы (в C++ это было отмечено как
> недоработка) — например, по TTL.

Лимит `0` = без ограничений (грант = want сразу).

### 5.7. `watcher` (был `fs_watcher.*`) — упрощается через fsnotify

C++ вручную вёл inotify (рекурсивные вотчи, `IN_IGNORED`, дебаунс). В Go:

```go
w, _ := fsnotify.NewWatcher()
// добавить root и все подкаталоги рекурсивно (fsnotify НЕ рекурсивен сам)
```

- fsnotify не рекурсивен: при `Create` каталога — `w.Add(newDir)` **и всех его
  подкаталогов** (баг C++: при переносе готового дерева вотчились не все подкаталоги
  — сделайте рекурсивный обход при добавлении).
- Маппинг событий: `Create`|`Rename`(в) → `CREATED`; `Write`(закрытие) →
  `MODIFIED`; `Remove`|`Rename`(из) → `REMOVED`. Для файла игнорируйте «полу-запись»
  (в C++ ждали `IN_CLOSE_WRITE`; в fsnotify — `Write`, но событий может быть
  несколько → дебаунс).
- **Дебаунс** по `(vpath)` в окне `events.debounce_ms` — совпадающие пути
  подавлять.
- Событие → колбэк сервера: инвалидировать checksum-кэш VFS + `broadcast(SUB_FS,
  EVENT_FS)`.
- Запуск/остановка через `context.Context` + горутина; на выходе — `w.Close()`.
- На не-Linux fsnotify работает (kqueue/Windows) — бонус против C++-заглушки.

### 5.8. `client` (был `client.*`)

Блокирующий транспорт: `Connect` (TCP+HELLO+AUTH), `ListDir/Stat/Checksum`,
`Download` (с докачкой `.part`), admin-вызовы, `Subscribe`, `PollEvents`, `Ping`.

- **Обработка асинхронных кадров.** `recvExpect(want)` — цикл: прочитать кадр;
  если это `EVENT_*`/`PONG` — отдать в `eventHandler` и продолжить; `ERROR` →
  вернуть `error` с `ErrCode`; иначе если тип == want — вернуть; иначе ошибка.
  То же в цикле `Download` (пропускать события между чанками).
- `PollEvents(timeout)` — для простоя: `SetReadDeadline`, прочитать кадр; **только
  асинхронные** отдавать в handler (баг C++: отдавали любой кадр). Возврат:
  `NONE`/`EVENT`/`CLOSED`.
- `Download`: если есть `<local>.part` — `offset = размер .part`, докачка;
  писать в `.part`; на `DOWNLOAD_DONE` сверить контрольную сумму собранного файла;
  при успехе — атомарно `os.Rename(.part → local)`; при несовпадении —
  **удалить `.part`** (баг C++: битый полноразмерный `.part` зацикливался);
  ограничить приём по `total_size` (защита от бесконечного стрима).
- `Interrupt()` — закрыть/полузакрыть соединение, чтобы разбудить заблокированное
  чтение из другой горутины (для быстрого выхода из TUI посреди закачки). В Go —
  `conn.SetReadDeadline(time.Now())` или `conn.Close()`.
- `RemoteError` — тип с `ErrCode` + сообщением.

### 5.9. `tui` (был `tui/model.*`, `view.*`, `connection.*`) → Bubble Tea

**Ключевое совпадение:** ваш C++-дизайн уже был Elm-архитектурой. Перенос почти
дословный:

| C++ (tui) | Bubble Tea |
|---|---|
| `AppState` (чистое состояние без FTXUI) | `Model` |
| `Command` (UI→worker: `CmdListDir`, `CmdDownload`, `CmdAdmin*`) | `tea.Cmd` (функции, возвращающие `tea.Msg`) |
| `Result` (worker→UI: `ResListing`, `ResProgress`, `ResEvent`, …) | `tea.Msg` (типы, обрабатываемые в `Update`) |
| `AppState::apply(Result)` | `Model.Update(msg) (Model, tea.Cmd)` |
| `render_commander`/`render_admin` (чистые функции) | `Model.View() string` (+ Lip Gloss для цвета) |
| `Connection` (worker-поток + очередь) | горутина, шлющая `tea.Msg` через `p.Send(msg)` (`program.Send`) |

- **Модель:** две панели (`Panel{source, path, entries, cursor, ...}`), лог
  операций, прогресс, статус связи (`Link`), состояние админ-панели (вкладки
  Overview/Clients/Settings).
- **Панели и IFs:** локальная панель читает ФС синхронно (`os.ReadDir`), удалённая
  — асинхронно: `Update` возвращает `tea.Cmd`, который в горутине зовёт
  `client.ListDir` и шлёт `resListingMsg`.
- **Сеть строго вне UI:** весь `client.*` живёт в отдельной горутине; общение с
  Bubble Tea — через `program.Send(msg)` (потокобезопасно) — это ваш
  «inbox + PostEvent» из C++.
- **Клавиши** (в `Update`): Tab (сменить панель), стрелки/PgUp-Dn/Home/End,
  Enter (cd/вниз), Space (пометка), F5 (скачать), F9 (админ, если ADMIN),
  Ctrl+R (обновить), F10/Esc (выход/назад). MC-семантика.
- **Live-события:** горутина клиента крутит `PollEvents` в простое + heartbeat
  (PING раз в ~20 c) + **авто-реконнект** с backoff и повторной подпиской; при
  реконнекте перечитать показанную директорию. По `EVENT_FS` в текущем каталоге —
  перечитать панель, подсветить новое (жёлтым).
- **Цвет/вид:** Lip Gloss. Новые файлы — жёлтым с `*`; ошибки — красным в логе
  (не исчезают молча); индикатор связи зелёный/жёлтый/красный; прогресс-бар со
  скоростью и ETA; полоса F-клавиш; строка-приглашение `login@host:path$`.
- **Админ-панель (F9):** вкладки Обзор/Клиенты(kick)/Настройки; правка hot-ключа
  через `textinput`-модалку → `ADMIN_SET`. По `EVENT_CONFIG` — обновлять.
- **Профили:** `~/.config/fileshare/profiles.json` (`XDG_CONFIG_HOME`/`HOME`),
  права `0600`. Пароль по умолчанию не хранить.
- **`--batch`** режим (без TUI): connect + `--list`/`--get` для скриптов; пароль
  из `--password`/`FILESHARE_PASSWORD`/промпта.

> Альтернатива Bubble Tea — `github.com/rivo/tview` (ближе к FTXUI по «виджетам»).
> Но Bubble Tea лучше ложится на ваш существующий `AppState`/`Command`/`Result`.

### 5.10. `cmd/fshare-daemon` (был `daemon_main.cpp`)

Флаги: `--config`, `--port`, `--share-root`, `--check-config`, `--log-level`,
`--add-user LOGIN --role`, `--reset-password LOGIN`. Пароль читать без эха
(`golang.org/x/term.ReadPassword`). Сигналы через `signal.NotifyContext`
(`SIGINT/SIGTERM` → отмена контекста; `SIGHUP` → выставить флаг reload, который
accept-loop подхватит и вызовет `ctx.ReloadConfig()`). Логирование — `log/slog`
(структурный, уровни) в stderr → journald/docker.

### 5.11. `cmd/fshare-commander` (был `commander_main.cpp`)

`tea.NewProgram(model, tea.WithAltScreen())`. Экран входа (host/port/login/пароль
+ профили) → командер. `--batch` ветка без Bubble Tea.

---

## 6. Модель конкурентности

Таблица перевода:

| C++ | Go |
|---|---|
| поток-на-соединение (`std::thread`, detach) | горутина-на-соединение (`go handleConn(...)`) |
| `std::mutex` / `lock_guard` | `sync.Mutex` / `defer mu.Unlock()` |
| `std::atomic<T>` | `sync/atomic` (`atomic.Uint64`, `atomic.Pointer[T]`, `atomic.Bool`) |
| `condition_variable` (дренаж хендлеров) | `sync.WaitGroup` (`wg.Add/Done/Wait`) |
| per-session send-mutex + `try_lock` | исходящий канал `chan []byte` + горутина-писатель |
| очередь команд + CV (worker) | канал команд (`chan Command`) + `select` |
| `accepting_` флаг + `wait_readable` таймаут | `context.Context` + `net.Listener.Accept` в горутине, `ctx.Done()` |
| `net::shutdown_handle` для разблокировки recv | `conn.SetDeadline`/`conn.Close` |
| graceful drain (grace + join) | `context` с таймаутом + `wg.Wait()` |

**Правила Go, чтобы не наступить на грабли:**
- Каждая горутина, которую вы стартуете, должна быть **дождана** перед
  завершением владельца ресурсов (`WaitGroup`). Не «detach и забыть».
- Общее изменяемое состояние — только через atomics/каналы/мьютексы; гоняйте
  тесты под `go test -race` (аналог TSan) — он найдёт ровно тот класс гонок,
  что нашёл TSan в C++.
- Снапшот-конфиг: только `atomic.Pointer[Settings]`; писатели — под одним
  мьютексом.

---

## 7. Безопасность

- **Confinement путей** — `os.Root` (Go 1.24+). Все операции с файлами share —
  через `root.Open/Stat/OpenRoot`, **никогда** не собирайте путь строкой и не
  открывайте по строке после отдельной проверки (это был C++-TOCTOU, который в Go
  просто не возникает при использовании `os.Root`).
- **Constant-time** сравнение proof/StoredKey — `crypto/subtle.ConstantTimeCompare`.
- **CSPRNG** — `crypto/rand` для challenge/salt.
- **Пароли** — PBKDF2 (см. §5.3); на сервере хранится StoredKey, не пароль.
  Замедление и бан по IP от перебора.
- **Лимиты протокола** — oversize/битые кадры рвут только одно соединение;
  таймаут рукопожатия против slow-loris; `max_connections`,
  `max_sessions_per_user`.
- **Права процесса** — демон под отдельным пользователем, share read-only (до
  upload); в Docker — non-root, `FROM scratch`.
- Restart-ключи (`server.port`, `server.share_root`) **нельзя** менять по сети —
  только рестарт (защита от угона админ-сессии).

---

## 8. Чек-лист багов

Это реальные баги, найденные в C++ двумя раундами adversarial-ревью и
исправленные. **Go-порт обязан обработать те же случаи** (в Go часть исчезает
сама, часть — нет):

| # | Баг (C++) | В Go |
|---|---|---|
| 1 | detached-поток переживал контекст → use-after-free | GC снимает UAF, но **дождитесь горутин** (`WaitGroup`) перед закрытием ресурсов |
| 2 | `current_path` не очищался при исключении в checksum → сессия «навечно downloading», дренаж висит | **`defer`** очистки `curPath` |
| 3 | клиент: rename→copy-fallback игнорировал ошибку → «успех» без файла | проверяйте ошибку `os.Rename`; успех только если файл на месте |
| 4 | at-capacity `send_error` вне try/catch → падение демона | в Go паники не будет, но игнорируйте ошибку записи отвергнутому клиенту |
| 5 | `current_path` ставился после ACCEPT / снимался до DONE → дренаж путал активную передачу с простоем | ставить до ACCEPT, снимать после DONE (или `defer`) |
| 6 | докачка: offset > нового (укоротившегося) размера → застревало | на `UNSUPPORTED_OFFSET` при offset>0 — удалить `.part` и начать заново |
| 7 | `max_connections` по отстающему `size()` | считайте активные соединения атомарно/через `WaitGroup`-счётчик до старта |
| 8 | клиент писал чанки без проверки суммарного размера vs `total_size` | ограничьте приём `total_size` |
| 9 | **TOCTOU:** `resolve()` проверял строку, а открывали заново по строке → подмена симлинка-компонента выводила за корень | **`os.Root`** закрывает это by design |
| 10 | гонка config: `apply()` (SIGHUP) без мьютекса терял апдейт `Set()` | оба под одним `wmu` |
| 11 | `per_client_bps` лимитировал на передачу, не на клиента → N закачек = N×лимита | один bucket на клиента (ключ = логин) |
| 12 | `Session::send` мог писать в закрытый/переиспользованный fd (broadcast держал ссылку) | канал `out` + горутина-писатель: при закрытии соединения горутина выходит, никто не пишет в мёртвый fd |
| 13 | сужение u64→u32 конфиг-значения до валидации → тихий wrap | проверяйте диапазон до присваивания |
| 14 | неатомарная запись конфига (truncate-then-write) → рваное чтение при SIGHUP | `os.CreateTemp` + `os.Rename` |
| 15 | fsnotify/inotify: перенос готового дерева вотчил не все подкаталоги; не чистились стухшие вотчи | рекурсивно `w.Add` при `Create`/`Rename` каталога; на `Remove` — снять вотч |
| 16 | quit TUI висел до конца активной закачки | `conn.SetDeadline`/`Close` для разблокировки; отмена контекста |

**Известные ограничения C++, которые Go может закрыть «бесплатно»:**
- медленный клиент тормозил broadcast (в C++ — синхронный send) → в Go
  **неблокирующая** отправка в per-session канал `out` (`select … default`);
- рост карты rate-bucket'ов → добавьте TTL-очистку;
- перебазирование inotify-вотчей при rename каталога → обрабатывайте `Rename`.

---

## 9. Тестирование и порядок работ

**Порядок (те же вертикальные срезы, что M7–M11):**
1. `proto` + round-trip/negative тесты. Затем `vfs` (через `os.Root`) с тестами
   traversal/симлинк.
2. `server` + `client` минимальные: рукопожатие (no-auth), `ListDir`, `Download`
   с докачкой; интеграционный тест на эфемерном порту (`net.Listen(":0")`).
3. `auth`: KAT-векторы, challenge-response, бан, `max_sessions_per_user`.
4. `tui` (Bubble Tea): `Model.Update` тестируется как чистая функция без
   терминала; `View()` рендерится в строку (Bubble Tea — `teatest`/просто вызов
   `View()`); `--batch` — e2e против живого демона.
5. `watcher` + live-события: интеграционный тест «создали файл → пришёл
   `EVENT_FS`»; **обязательно** тест «событие посреди закачки не портит поток».
6. `config`/`ratelimit`/admin: снапшоты, отказ restart-ключей, **флагманский
   тест** — смена лимита реально тормозит **активную** закачку.

**Инструменты:**
- `go test -race ./...` — обязательно (аналог TSan). Найдёт гонки классов,
  которые TSan нашёл в C++.
- Таблично-управляемые тесты (`[]struct{name; in; want}`) — идиома Go для
  round-trip/negative.
- Интеграция: поднимайте сервер в горутине на `:0`, берите
  `listener.Addr().(*net.TCPAddr).Port`.
- Совместимость (мощно): проверьте, что **Go-клиент** ходит на **C++-демон** и
  наоборот — если протокол реализован байт-в-байт, всё работает. Это лучший тест
  корректности `proto`.

Перенесите содержательные кейсы из `test_v2_*.cpp` (см. список файлов в §5-ссылках)
— особенно negative/adversarial (traversal, oversize, replay, событие-в-закачке,
живой лимит).

---

## 10. Сборка и деплой

Огромный выигрыш Go:

```bash
go build ./cmd/fshare-daemon ./cmd/fshare-commander     # локально
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fshare-daemon ./cmd/fshare-daemon   # статический бинарь под VPS
```

**Docker** сжимается до:

```dockerfile
FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/fshare-daemon ./cmd/fshare-daemon

FROM scratch
COPY --from=build /out/fshare-daemon /fshare-daemon
EXPOSE 5555
ENTRYPOINT ["/fshare-daemon", "--config", "/data/config.json", "--share-root", "/data/share", "--port", "5555"]
```

(`FROM scratch` возможен при `CGO_ENABLED=0`; если нужен TLS с системными
корнями — `FROM gcr.io/distroless/static`.) `docker-compose.yml` — как в C++,
`stop_grace_period: 90s` под graceful-дренаж, `STOPSIGNAL SIGTERM`.

systemd-юнит — как в [03-server-daemon.md](03-server-daemon.md), `ExecReload=
/bin/kill -HUP $MAINPID`.

---

## 11. Библиотеки

| Задача | Пакет | Почему |
|---|---|---|
| Confinement путей | `os.Root` (stdlib, Go 1.24+) | встроенный openat2; иначе `github.com/cyphar/filepath-securejoin` |
| PBKDF2 / Argon2 | `golang.org/x/crypto/pbkdf2` (+ `/argon2` для perspective) | стандарт |
| Constant-time | `crypto/subtle` (stdlib) | — |
| Rate limit | `golang.org/x/time/rate` | готовый token bucket с `SetLimit` на лету |
| Наблюдение ФС | `github.com/fsnotify/fsnotify` | кроссплатформенно |
| TUI | `github.com/charmbracelet/bubbletea` + `lipgloss` (+ `bubbles/textinput`, `progress`) | Elm-архитектура = ваш дизайн; либо `rivo/tview` |
| Пароль без эха | `golang.org/x/term` | — |
| Логи | `log/slog` (stdlib) | структурные, уровни |
| Сигналы/отмена | `os/signal.NotifyContext` (stdlib) | graceful shutdown |
| JSON | `encoding/json` (stdlib) | конфиг/users/profiles |
| Бинарная сериализация | `encoding/binary` (stdlib) | BE-фрейминг |

Держите зависимости минимальными: `bubbletea`+`lipgloss`+`fsnotify`+
`x/crypto`+`x/time`+`x/term` — почти всё остальное stdlib.

---

## 12. Приложения

### 12.1. Схема `config.json`

```jsonc
{
  "server":   { "port": 5555, "share_root": "./share", "workers": 0, "motd": "" },
  "limits":   { "max_connections": 200, "max_sessions_per_user": 3,
                "per_client_bps": 0, "global_bps": 0,
                "handshake_timeout_s": 10, "idle_timeout_s": 600, "auth_fail_ban_s": 60 },
  "checksum": { "cache_file": "checksums.cache" },
  "events":   { "enabled": true, "debounce_ms": 500 },
  "auth":     { "users_file": "users.json", "pbkdf2_iters": 200000 },
  "log":      { "level": "info" }
}
```

Отсутствующий файл → все значения по умолчанию (это не ошибка).

**Hot-ключи** (менять по сети/SIGHUP можно): `limits.per_client_bps`,
`limits.global_bps`, `limits.max_connections`, `limits.max_sessions_per_user`,
`limits.handshake_timeout_s`, `limits.idle_timeout_s`, `limits.auth_fail_ban_s`,
`server.motd`, `log.level`, `events.debounce_ms`.
**Restart-ключи** (только рестарт): `server.port`, `server.share_root`,
`server.workers`, `checksum.cache_file`, `auth.pbkdf2_iters`, `auth.users_file`.

`Validate()`: `port ∈ [1,65535]`, `share_root` не пуст, если `global_bps>0` то
`per_client_bps ≤ global_bps`, таймауты > 0.

### 12.2. Схема `users.json`

```jsonc
{
  "users": [
    { "login": "admin", "role": "admin",
      "stored_key": "<64 hex = SHA256(ClientKey)>", "enabled": true }
  ]
}
```

`role` ∈ {`admin`,`user`}. Отсутствующий/пустой файл → **no-auth bootstrap**
(любой вход → ADMIN; в `HELLO_OK` `auth_mode=NONE`).

### 12.3. Схема `profiles.json` (клиент, `~/.config/fileshare/`, права 0600)

```jsonc
{
  "profiles": [
    { "name": "vps", "host": "vps.example.com", "port": 5555, "login": "vit",
      "last_seen": 1752537600, "downloads_dir": "" }
  ]
}
```

`last_seen` — unix-время последнего визита (для подсветки нового). Пароль по
умолчанию не хранится.

### 12.4. Соответствие C++-файлов и Go-пакетов

| C++ | Go-пакет |
|---|---|
| `protocol.{hpp,cpp}`, `wire.{hpp,cpp}` | `internal/proto` |
| `vfs.{hpp,cpp}` | `internal/vfs` (обёртка `os.Root`) |
| `crypto.{hpp,cpp}`, `auth.{hpp,cpp}` | `internal/auth` |
| `settings.{hpp,cpp}`, `settings_hub.{hpp,cpp}` | `internal/config` |
| `rate_limiter.{hpp,cpp}` | `internal/ratelimit` |
| `fs_watcher.{hpp,cpp}` | `internal/watcher` (fsnotify) |
| `session.{hpp,cpp}`, `dispatch.{hpp,cpp}`, `server_context.{hpp,cpp}`, `server.{hpp,cpp}` | `internal/server` |
| `client.{hpp,cpp}` | `internal/client` |
| `tui/model.*`, `tui/view.*`, `tui/connection.*` | `internal/tui` (Bubble Tea) |
| `daemon_main.cpp` | `cmd/fshare-daemon` |
| `commander_main.cpp` | `cmd/fshare-commander` |
| `log.{hpp,cpp}` | `log/slog` (stdlib) |

---

### Итог

Переписывание — это в основном (1) точное воспроизведение протокола из §4, (2)
замена ручных системных кусков на `os.Root`/`crypto`/`fsnotify`/`x/time/rate`,
(3) перенос Elm-архитектуры TUI в Bubble Tea, (4) прохождение чек-листа багов из
§8 и прогон `go test -race`. Ориентир по объёму — заметно меньше 6.4k строк C++.
Лучший критерий готовности: **Go-клиент ↔ C++-демон работают друг с другом**, и
флагманский тест «живой лимит тормозит активную закачку» зелёный.
