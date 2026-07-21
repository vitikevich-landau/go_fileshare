# 02. Протокол v2

## 1. Общие положения

Фрейминг наследуется от v1 без изменений — каждое сообщение:

```
┌────────┬──────────────────────────┬───────────┐
│msg_type│ payload_length (u32, BE)  │  payload  │
│ 1 байт │        4 байта            │  N байт   │
└────────┴──────────────────────────┴───────────┘
```

- Все числа — big-endian, сериализация явная (как в `protocol.hpp` v1).
- Строки — `len:u16` + UTF-8 байты (пути могут быть длиннее алиасов v1:
  `MAX_PATH_LEN = 4096`).
- `MAX_CONTROL_PAYLOAD` поднимается до **4 MiB** (листинг большой директории);
  `CHUNK_SIZE` остаётся 64 KiB.
- Любой malformed-вход → `ProtocolError` → разрыв только этого соединения (правило v1).
- **Версионирование**: первым сообщением клиент обязан прислать `HELLO`. Сервер v2,
  получив первым байтом код v1 (`0x01 LIST_REQUEST`), отвечает
  `ERROR(UNSUPPORTED_VERSION)` и закрывает соединение — старые клиенты получают
  внятный отказ, а не мусор.

## 2. Карта сообщений

Коды v1 (0x01–0x08) в v2 **не переиспользуются** под другие смыслы — это дешёвая
страховка от путаницы при отладке. Новые диапазоны:

| Группа | Коды | Мин. роль |
|---|---|---|
| Handshake / auth | `0x10–0x1F` | anonymous |
| Файловая система | `0x20–0x2F` | user |
| Передача данных | `0x30–0x3F` | user |
| События (push) | `0x40–0x4F` | user |
| Админ-канал | `0x50–0x5F` | admin |
| Служебные | `0x07/0x08` (PING/PONG из v1), `0x06` ERROR | anonymous |

### 2.1. Handshake и аутентификация

| Сообщение | Код | Направление | Payload |
|---|---|---|---|
| `HELLO` | `0x10` | C→S | `proto_ver:u16`, `client_name:str` |
| `HELLO_OK` | `0x11` | S→C | `proto_ver:u16`, `server_name:str`, `auth_mode:u8` (0=none, 1=challenge), `challenge:16 байт`, `salt_login_hint:u8` (0/1 — см. §6 security) |
| `AUTH_REQUEST` | `0x12` | C→S | `login:str`, `proof:32 байта` (HMAC-SHA-256, см. [06-security.md](06-security.md)) |
| `AUTH_OK` | `0x13` | S→C | `role:u8` (1=user, 2=admin), `session_id:u64`, `motd:str` |
| `AUTH_FAIL` | `0x14` | S→C | `reason:u16`, `message:str`; после 3 неудач — разрыв + временный бан IP (настройка) |

Состояния соединения: `CONNECTED → HELLO_RECEIVED → AUTHED(role)`.
До `AUTHED` допускаются только `HELLO`, `AUTH_REQUEST`, `PING`. Таймаут handshake —
`limits.handshake_timeout_s` (по умолчанию 10 с).

### 2.2. Файловая система (замена плоского LIST)

| Сообщение | Код | Направление | Payload |
|---|---|---|---|
| `LIST_DIR_REQUEST` | `0x20` | C→S | `path:str` (абсолютный внутри share, `/` = корень) |
| `LIST_DIR_RESPONSE` | `0x21` | S→C | `path:str`, `count:u32`, далее записи (см. ниже) |
| `STAT_REQUEST` | `0x22` | C→S | `path:str` |
| `STAT_RESPONSE` | `0x23` | S→C | одна запись `DirEntry` |
| `CHECKSUM_REQUEST` | `0x24` | C→S | `path:str` — checksum считается лениво, поэтому вынесен из листинга |
| `CHECKSUM_RESPONSE` | `0x25` | S→C | `path:str`, `algo:u8` (1=CRC32, 2=SHA-256), `checksum:32 байта` |

Запись `DirEntry`:

```
name:str · kind:u8 (0=file, 1=dir) · size:u64 · mtime:u64 (unix, сек) · flags:u8
```

`flags`: bit0 = «новый» (mtime > порога, который клиент передал в `SUBSCRIBE`;
дублирует клиентскую логику подсветки для простых клиентов), остальные биты — резерв.

Правила путей (сервер обязан валидировать):
- только нормализованные пути: без `..`, без `//`, без символов `\0`;
- запрос вне share-root → `ERROR(ACCESS_DENIED)`;
- симлинки, ведущие наружу из share-root, не раскрываются (realpath-проверка).

### 2.3. Передача данных

| Сообщение | Код | Направление | Payload |
|---|---|---|---|
| `DOWNLOAD_REQUEST` | `0x30` | C→S | `path:str`, `offset:u64` |
| `DOWNLOAD_ACCEPT` | `0x31` | S→C | `transfer_id:u32`, `total_size:u64` — клиент заранее знает размер для прогресс-бара |
| `CHUNK_DATA` | `0x32` | S→C | `transfer_id:u32`, затем сырые байты (до CHUNK_SIZE) |
| `DOWNLOAD_DONE` | `0x33` | S→C | `transfer_id:u32`, `algo:u8`, `checksum:32 байта` |
| `DOWNLOAD_CANCEL` | `0x34` | C→S | `transfer_id:u32` — отмена без разрыва соединения (в v1 приходилось рвать сокет) |

Отличия от v1:
- `transfer_id` — задел под несколько параллельных передач в одном соединении;
  в v2.0 разрешена одна активная передача, но формат уже готов.
- `DOWNLOAD_ACCEPT` устраняет неловкость v1, где размер был известен только из листинга.
- Докачка по `offset` — как в v1 (сервер шлёт checksum всего файла; клиент при
  докачке дочитывает локальную часть для инкрементального хэша — логика v1 сохраняется).

### 2.4. События (server push)

Ключ к «чтобы новое бросалось в глаза»: сервер сам сообщает об изменениях,
клиент не опрашивает.

| Сообщение | Код | Направление | Payload |
|---|---|---|---|
| `SUBSCRIBE` | `0x40` | C→S | `mask:u32` (bit0=fs-события, bit1=серверные уведомления, bit2=конфиг (admin)) |
| `EVENT_FS` | `0x41` | S→C | `op:u8` (1=created, 2=modified, 3=removed), `kind:u8`, `path:str`, `size:u64`, `mtime:u64` |
| `EVENT_NOTICE` | `0x42` | S→C | `severity:u8` (info/warn/error), `text:str` — «сервер уходит на shutdown через 60 с» и т.п. |
| `EVENT_CONFIG` | `0x43` | S→C | `key:str`, `new_value:str` — только подписчикам-админам |

Источник `EVENT_FS` на сервере — inotify-наблюдатель за share-root (рекурсивно,
с дебаунсом 500 мс, чтобы копирование большого файла не сыпало событиями).
Клиент, получив `EVENT_FS` по текущей директории панели, обновляет её и
подсвечивает изменившиеся записи.

### 2.5. Админ-канал

См. [05-admin.md](05-admin.md). Кратко:

| Сообщение | Код | Payload |
|---|---|---|
| `ADMIN_GET_CONFIG` | `0x50` | пусто → `ADMIN_CONFIG` `0x51`: `json:str` (текущий эффективный конфиг) |
| `ADMIN_SET` | `0x52` | `key:str`, `value:str` (JSON-значение) → `ADMIN_SET_RESULT` `0x53`: `ok:u8`, `message:str` |
| `ADMIN_LIST_CLIENTS` | `0x54` | пусто → `ADMIN_CLIENTS` `0x55`: список сессий (id, login, ip, роль, что качает, байт передано, скорость) |
| `ADMIN_KICK` | `0x56` | `session_id:u64` → результат |
| `ADMIN_STATS` | `0x57` | пусто → `ADMIN_STATS_RESPONSE` `0x58`: аптайм, байт отдано, активные/завершённые закачки, соединения, версия, текущие лимиты |
| `ADMIN_SHUTDOWN` | `0x59` | `grace_seconds:u32` — graceful shutdown с дренажом (логика v1 M5) |

### 2.6. Ошибки

`ERROR` (`0x06`) сохраняется, коды расширяются:

```
OK=0, FILE_NOT_FOUND=1, UNSUPPORTED_OFFSET=2, BAD_REQUEST=3, INTERNAL_ERROR=4,
UNSUPPORTED_VERSION=5, AUTH_REQUIRED=6, AUTH_FAILED=7, ACCESS_DENIED=8,
NOT_A_DIRECTORY=9, IS_A_DIRECTORY=10, RATE_LIMITED=11, SERVER_SHUTTING_DOWN=12,
QUOTA_EXCEEDED=13 (резерв под M13)
```

## 3. План реализации протокола

1. **`protocol_v2.hpp/cpp`** рядом с v1 (v1 не трогаем, пока живы его тесты):
   энкодеры/парсеры новых сообщений на существующих `ByteReader`/`write_*`.
2. Юнит-тесты по образцу `test_protocol.cpp`: round-trip каждого сообщения +
   отказ на битом вводе (усечённый payload, oversize, мусорный тип, `..` в пути).
3. Fuzz-мини-тест: случайные байты в `decode_frame` не должны ронять процесс
   (расширение подхода fault-injection из M5).
4. После стабилизации v2 — удаление кодов v1 и старых энкодеров (отдельный коммит).
