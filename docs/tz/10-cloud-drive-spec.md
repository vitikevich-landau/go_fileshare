# 10. Развитие FShare Commander до консольного облачного диска

> **Статус документа:** целевая спецификация M12–M18.  
> **Исходная точка:** M7–M11 реализованы; сервер безопасно раздаёт дерево каталогов,
> клиент умеет просматривать и скачивать файлы, есть аутентификация, live-события,
> авто-реконнект, rate limiting и админ-канал.  
> **Цель:** превратить read-only fileshare в самодостаточный многопользовательский
> облачный диск с консольным интерфейсом, не ломая совместимость протокола v2.

Документ задаёт не только список функций, но и обязательные инварианты,
состояния операций, схему хранения, границы пакетов, поведение при сбоях и
критерии готовности. Если реализация расходится с этим документом, расхождение
должно быть отдельно зафиксировано в ADR или в обновлении спецификации.

---

## 1. Цель продукта

FShare Commander должен позволять владельцу сервера развернуть личное облачное
хранилище на одном VPS или домашнем сервере, а пользователям — работать с ним
из терминала.

Итоговая система должна поддерживать:

1. отдельное пространство каждого пользователя;
2. общий публичный каталог с контролируемыми правами;
3. загрузку и скачивание больших файлов с докачкой;
4. создание, копирование, перемещение, переименование и удаление объектов;
5. квоты и корректный учёт занятого места при параллельных операциях;
6. корзину и историю версий;
7. шифрование транспорта;
8. публичные ссылки через HTTPS;
9. журнал изменений и двустороннюю синхронизацию;
10. администрирование пользователей без ручного редактирования JSON;
11. восстановление после падения без появления частично опубликованных файлов.

### 1.1. Целевой сценарий первой законченной версии

Минимально законченной облачной версией считается M15:

- администратор создаёт пользователя и назначает квоту;
- пользователь входит по защищённому TLS-соединению;
- видит только свой home и разрешённый public;
- загружает файл, прерывает передачу и продолжает её;
- скачивает файл с докачкой;
- создаёт каталоги, перемещает, копирует и удаляет объекты;
- удалённое попадает в корзину;
- перезапись создаёт предыдущую версию;
- после аварийного перезапуска метаданные и файловая система согласованы;
- все критические сценарии покрыты интеграционными тестами с `-race`.

### 1.2. Что не входит в ближайший scope

До завершения M18 сознательно не реализуются:

- кластер из нескольких daemon-узлов;
- S3/Swift/Ceph backend;
- блоковая дедупликация между пользователями;
- delta-transfer изменившихся блоков;
- end-to-end encryption, при котором сервер не видит содержимое;
- браузерный файловый менеджер;
- офисный редактор и совместное редактирование документов;
- медиатранскодирование и предпросмотр видео;
- публичная самостоятельная регистрация пользователей;
- биллинг.

Архитектура не должна делать эти функции невозможными, но код под них заранее
не пишется.

---

## 2. Термины и основные инварианты

### 2.1. Термины

- **UserID** — стабильный числовой идентификатор пользователя. Логин может
  измениться, UserID — нет.
- **ResourceID** — стабильный идентификатор файла или каталога. Путь может
  измениться после rename/move, ResourceID — нет.
- **Revision** — монотонно возрастающая версия содержимого ресурса.
- **VirtualPath** — путь, который видит клиент: `/home/...` или `/public/...`.
- **StoragePath** — внутренний путь под data root; клиент никогда его не получает.
- **UploadID** — случайный UUID одной незавершённой загрузки.
- **ChangeSeq** — глобальный монотонный номер записи журнала изменений.
- **Quota reservation** — временно зарезервированный объём для незавершённой
  загрузки.
- **Published file** — файл, который уже атомарно появился в пользовательском
  дереве и имеет согласованную запись в БД.
- **Trash entry** — логически удалённый объект, доступный для восстановления.
- **Version blob** — сохранённое содержимое предыдущей ревизии.

### 2.2. Обязательные инварианты

1. Клиент никогда не может обратиться к StoragePath напрямую.
2. Ни один путь пользователя не может выйти за его `os.Root`.
3. Частично загруженный файл никогда не виден в обычном листинге.
4. Успешный ответ на commit означает, что файл опубликован, метаданные записаны,
   а квота учтена.
5. После ошибки или падения допустимы временные служебные файлы, но недопустимы
   «успешные» метаданные без файла или опубликованный файл, принадлежащий другому
   пользователю.
6. Повтор идентичного идемпотентного запроса не должен повторно применять
   мутацию.
7. Два параллельных upload не могут оба зарезервировать один и тот же остаток
   квоты.
8. `used_bytes + reserved_bytes <= quota_bytes`, если квота не равна нулю.
9. События и sync-журнал фильтруются теми же правилами видимости, что и листинг.
10. Любой malformed input рвёт только одно соединение и не роняет daemon.
11. Секреты, пароли и bearer-токены никогда не записываются в обычный лог.
12. v2 остаётся byte-for-byte совместимым с существующими Go/C++ клиентами.

---

## 3. Стратегия совместимости: v2 остаётся, новые функции идут в v3

Расширять текущий v2 новыми сообщениями без явной договорённости нельзя: его
ценность — совместимость с эталонной C++-реализацией.

### 3.1. Поведение сервера

Daemon должен принимать два варианта handshake:

- `HELLO ProtoVersion=2` — существующее read-only поведение M7–M11;
- `HELLO ProtoVersion=3` — облачные функции M12+.

Сервер не пытается автоматически «догадаться» о возможностях клиента по
неизвестным сообщениям.

### 3.2. Capability negotiation

После `AUTH_OK` клиент v3 отправляет:

```text
CAPABILITIES_REQUEST
```

Сервер отвечает битовой маской и ограничениями:

```go
type CapabilitiesResponse struct {
    Features            uint64
    MaxControlPayload   uint32
    ChunkSize           uint32
    MaxParallelTransfer uint16
    MaxPageSize         uint32
}
```

Минимальные feature bits:

```go
const (
    CapUpload uint64 = 1 << iota
    CapMutations
    CapQuota
    CapTrash
    CapVersions
    CapChangeJournal
    CapPublicLinks
    CapTLSRequired
)
```

Клиент обязан скрывать или блокировать UI-действия, которых сервер не объявил.

### 3.3. RequestID

Каждый v3 control request и его response несут `RequestID uint64`.

Требования:

- ID уникален в пределах активного соединения;
- клиент генерирует его монотонно;
- сервер возвращает тот же ID в response/error;
- асинхронные EVENT-сообщения имеют `RequestID=0`;
- сервер хранит небольшой TTL-кэш результатов идемпотентных мутаций по
  `(SessionID, RequestID)`;
- повтор запроса после сетевого обрыва допускается только для операций,
  объявленных идемпотентными.

На первом этапе control connection может оставаться последовательным. RequestID
закладывается сразу, чтобы позже разрешить multiplexing без очередной смены
протокола.

### 3.4. Новые семейства сообщений

Рекомендуемое распределение кодов v3:

```text
0x60–0x6F  capabilities, quota, paging
0x70–0x7F  upload
0x80–0x8F  mutations
0x90–0x9F  trash and versions
0xA0–0xAF  change journal and sync
0xB0–0xBF  public links
0xC0–0xCF  user administration
```

Точные коды и wire layout фиксируются отдельной таблицей в `internal/proto`
до начала реализации хендлеров. Для каждого сообщения обязательны:

- encode/decode round-trip;
- malformed/truncated/oversize tests;
- documented max payload;
- min role;
- allowed connection state;
- idempotency class.

---

## 4. Целевая архитектура и бинарные файлы

### 4.1. Бинарные файлы

```text
cmd/
  fshare-daemon/       основной TCP/TLS daemon
  fshare-commander/    интерактивный TUI и batch-команды
  fshare-sync/         фоновая двусторонняя синхронизация
  fshare-gateway/      HTTPS endpoint публичных ссылок
  fshare-admin/        опциональная локальная CLI-утилита администратора
```

На M12–M15 `fshare-admin` может быть частью флагов daemon. К M16 админские
операции должны быть доступны и по защищённому протоколу, и через локальный CLI.

### 4.2. Новые внутренние пакеты

```text
internal/
  metadata/        SQLite, миграции, транзакции, репозитории
  storage/         layout data root, atomic publish, fsync, recovery
  users/           user service, roles, quotas, roots
  upload/          upload state machine and reservation
  mutations/       mkdir/move/copy/delete
  trash/           trash lifecycle
  versions/        version retention and restore
  changes/         durable journal and cursors
  syncer/          local sync engine used by fshare-sync
  shares/          public-link model and token verification
  gateway/         HTTP handlers for public links
  tlsconfig/       certificate loading, TOFU pinning helpers
  locks/           keyed locks/resource locks
```

Существующие пакеты меняются следующим образом:

- `internal/proto` получает v3 types/messages/codecs;
- `internal/vfs` становится read API над пользовательским root, а мутации
  переходят в отдельные сервисы;
- `internal/auth` отвечает только за доказательство владения секретом;
- `internal/server` оркестрирует сервисы, но не содержит SQL и прямой бизнес-логики;
- `internal/client` получает control API, transfer pool и v3 negotiation;
- `internal/tui` вызывает client API, не знает wire layout;
- `internal/watcher` остаётся механизмом live UI, но не источником истины для sync.

### 4.3. Dependency rule

Пакеты должны зависеть внутрь:

```text
cmd -> server/client/tui/gateway
server -> services + proto
services -> metadata/storage/domain
metadata/storage -> stdlib/SQLite driver
proto -> stdlib only
```

`metadata` не импортирует `server`, `client`, `tui` или `proto`.
Доменные ошибки сервисов преобразуются в wire error codes на границе server.

---

## 5. Хранилище на диске

### 5.1. Data root

Предлагаемый layout:

```text
data/
  metadata.db
  metadata.db-wal
  metadata.db-shm

  files/
    users/
      <user-id>/
        live/
    public/
      live/

  staging/
    uploads/
      <upload-id>.upart
      <upload-id>.json

  versions/
    <user-id>/
      <resource-id>/
        <revision>.blob

  trash/
    <user-id>/
      <trash-id>/

  certs/
  backups/
```

`live/` является корнем, который открывается через `os.OpenRoot`.

### 5.2. Требования к StoragePath

- компоненты строятся только из серверных ID;
- пользовательский логин никогда не используется как физическое имя каталога;
- никакие пользовательские строки не конкатенируются с data root;
- для переносимости используются относительные пути;
- симлинки в пользовательском дереве по умолчанию запрещены;
- устройства, FIFO, socket и прочие special files не публикуются.

### 5.3. Atomic publish

Публикация нового содержимого выполняется в таком порядке:

1. upload полностью записан в staging;
2. проверены размер и checksum;
3. staging-файл `Sync`;
4. подготовлен target temp рядом с конечным путём, если rename между файловыми
   системами невозможен;
5. старая версия при необходимости перенесена в versions;
6. новый файл переименован атомарно;
7. выполнен fsync родительской директории на платформах, где это поддерживается;
8. SQLite-транзакция фиксирует resource/revision/quota/change;
9. commit-marker удалён;
10. публикуется EVENT.

Поскольку файловая система и SQLite не дают общей транзакции, `storage` обязан
использовать recovery markers. При старте daemon выполняет reconciliation и
доводит операцию до одного из двух состояний: полностью commit или полностью
rollback.

### 5.4. Recovery marker

```go
type RecoveryRecord struct {
    OperationID string
    Kind        string
    UserID      int64
    ResourceID  string
    TempPath    string
    FinalPath   string
    BackupPath  string
    Phase       string
}
```

Фазы должны быть достаточно подробными, чтобы startup recovery был
детерминированным. Тесты обязаны уметь «убить» процесс после каждой фазы.

---

## 6. SQLite и модель метаданных

### 6.1. Общие требования

- SQLite работает в WAL mode;
- foreign keys включены;
- busy timeout настроен;
- schema version хранится в `schema_migrations`;
- все миграции forward-only и выполняются до начала listener;
- тяжёлые пересчёты не держат write transaction дольше необходимого;
- timestamps хранятся как Unix milliseconds или RFC3339 consistently;
- repository methods принимают `context.Context`.

Допустим pure-Go driver, чтобы сохранить `CGO_ENABLED=0`; выбор драйвера
фиксируется ADR с замером размера бинарника и производительности.

### 6.2. Таблица users

```sql
CREATE TABLE users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    login             TEXT NOT NULL UNIQUE,
    role              TEXT NOT NULL CHECK (role IN ('user','admin')),
    stored_key        BLOB NOT NULL,
    auth_iters        INTEGER NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    quota_bytes       INTEGER NOT NULL DEFAULT 0,
    used_bytes        INTEGER NOT NULL DEFAULT 0,
    reserved_bytes    INTEGER NOT NULL DEFAULT 0,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL
);
```

`quota_bytes=0` означает unlimited.

PBKDF2 iteration count переносится в запись пользователя. Это позволяет
увеличивать стоимость для новых/обновлённых паролей без одновременного
обесценивания всех существующих StoredKey.

### 6.3. Таблица resources

```sql
CREATE TABLE resources (
    id                TEXT PRIMARY KEY,
    owner_user_id     INTEGER,
    parent_id         TEXT,
    namespace         TEXT NOT NULL CHECK (namespace IN ('home','public')),
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('file','dir')),
    current_revision  INTEGER NOT NULL DEFAULT 0,
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    checksum_algo     TEXT,
    checksum          BLOB,
    storage_relpath   TEXT,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL,
    deleted_at_ms     INTEGER,
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(parent_id) REFERENCES resources(id),
    UNIQUE(namespace, owner_user_id, parent_id, name)
);
```

Для корневых каталогов вводятся заранее созданные resource records.

### 6.4. Uploads и reservations

```sql
CREATE TABLE uploads (
    id                  TEXT PRIMARY KEY,
    user_id             INTEGER NOT NULL,
    target_parent_id    TEXT NOT NULL,
    target_name         TEXT NOT NULL,
    expected_size       INTEGER NOT NULL,
    expected_checksum   BLOB,
    received_bytes      INTEGER NOT NULL DEFAULT 0,
    reserved_bytes      INTEGER NOT NULL,
    overwrite_mode      TEXT NOT NULL,
    state               TEXT NOT NULL,
    staging_relpath     TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

Допустимые states:

```text
created -> receiving -> verifying -> committing -> completed
                  \-> cancelled
                  \-> failed
                  \-> expired
```

### 6.5. Versions

```sql
CREATE TABLE versions (
    resource_id       TEXT NOT NULL,
    revision          INTEGER NOT NULL,
    size_bytes        INTEGER NOT NULL,
    checksum_algo     TEXT NOT NULL,
    checksum          BLOB NOT NULL,
    storage_relpath   TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    expires_at_ms     INTEGER,
    PRIMARY KEY(resource_id, revision),
    FOREIGN KEY(resource_id) REFERENCES resources(id)
);
```

### 6.6. Trash

```sql
CREATE TABLE trash_entries (
    id                 TEXT PRIMARY KEY,
    user_id            INTEGER NOT NULL,
    resource_id        TEXT NOT NULL,
    original_parent_id TEXT,
    original_name      TEXT NOT NULL,
    deleted_at_ms      INTEGER NOT NULL,
    expires_at_ms      INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

### 6.7. Change journal

```sql
CREATE TABLE changes (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER,
    namespace         TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    operation         TEXT NOT NULL,
    path              TEXT NOT NULL,
    old_path          TEXT,
    revision          INTEGER NOT NULL,
    actor_session_id  INTEGER,
    created_at_ms     INTEGER NOT NULL
);

CREATE INDEX changes_user_seq ON changes(user_id, seq);
```

Журнал не удаляется до тех пор, пока не истёк configured retention и не
сформирован snapshot baseline для sync-клиентов.

### 6.8. Public links

```sql
CREATE TABLE shares (
    id                  TEXT PRIMARY KEY,
    owner_user_id       INTEGER NOT NULL,
    resource_id         TEXT NOT NULL,
    token_hash          BLOB NOT NULL UNIQUE,
    password_hash       BLOB,
    allow_download      INTEGER NOT NULL DEFAULT 1,
    expires_at_ms       INTEGER,
    revoked_at_ms       INTEGER,
    created_at_ms       INTEGER NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(resource_id) REFERENCES resources(id)
);
```

В БД хранится только hash bearer token. Полный token показывается владельцу один
раз при создании.

---

## 7. Пользователи, роли и namespaces

### 7.1. Роли

Минимум две роли:

- `user` — операции в собственном home, чтение разрешённого public;
- `admin` — user-возможности плюс админ-канал.

Не следует вводить десятки ролей. Для точечных разрешений public позже
используется ACL.

### 7.2. Virtual roots

После входа клиент видит:

```text
/
  home/
  public/
```

`/home` привязан к `files/users/<UserID>/live`.
`/public` привязан к `files/public/live`.

Для v2-сессии сохраняется старый единый share root. v3-сессия получает
`UserContext`:

```go
type UserContext struct {
    UserID   int64
    Login    string
    Role     proto.Role
    HomeRoot *os.Root
}
```

### 7.3. Public ACL

Для M12 достаточно:

- admin: read/write;
- user: read-only.

В M16 вводится ACL:

```sql
(resource_id, subject_type, subject_id, permission)
```

Permissions:

```text
read
write
share
admin
```

Разрешение вычисляется от ресурса вверх до ближайшего explicit ACL, с
ограниченной глубиной и кэшем. Любое EVENT и journal query используют тот же
authorization service.

### 7.4. User administration

Новые админ-команды:

```text
user list
user add <login> --role user --quota 20GiB
user disable <login>
user enable <login>
user passwd <login>
user role <login> <user|admin>
user quota <login> <bytes|unlimited>
user delete <login> --retain-data|--purge
```

Удаление пользователя по умолчанию двухфазное:

1. disable;
2. revoke sessions/shares;
3. mark pending deletion;
4. purge отдельной подтверждённой командой.

### 7.5. Bootstrap safety

Пустая или отсутствующая user DB больше не должна автоматически открывать
анонимный admin-доступ.

Новое правило:

- normal mode: daemon отказывается стартовать без admin user;
- `--init-admin`: интерактивно создаёт первую запись и выходит;
- `--insecure-no-auth`: явно включает старый bootstrap только для dev/test и
  печатает заметное предупреждение;
- Docker example обязан создавать пользователя через secret/init step.

---

## 8. Upload protocol и state machine

### 8.1. Begin

```go
type UploadBegin struct {
    RequestID        uint64
    TargetPath       string
    ExpectedSize     uint64
    ChecksumAlgo     uint8
    ExpectedChecksum [32]byte
    OverwriteMode    uint8
    ClientUploadKey  [16]byte
}
```

`ClientUploadKey` — стабильный случайный ключ одной логической загрузки. Он
позволяет после reconnect найти уже созданный UploadID и не зарезервировать квоту
вторично.

Ответ:

```go
type UploadAccept struct {
    RequestID    uint64
    UploadID     [16]byte
    ResumeOffset uint64
    ChunkSize    uint32
    ExpiresAt    uint64
}
```

### 8.2. Проверки BeginUpload

Под одной SQLite write transaction:

1. авторизация target parent;
2. target name validation;
3. проверка conflict/overwrite mode;
4. проверка свободного места на реальном volume;
5. проверка пользовательской квоты;
6. увеличение `reserved_bytes`;
7. создание uploads row.

После transaction создаётся staging-файл. Если создание файла не удалось,
reservation компенсируется отдельной транзакцией. Startup reconciliation также
закрывает этот разрыв.

### 8.3. Передача чанков

Два допустимых transport-варианта:

1. отдельное transfer connection, привязанное к session token;
2. существующий connection, если negotiated parallelism равен 1.

Для первой реализации предпочтителен connection pool:

```text
control connection: list/stat/mutations/events/admin
transfer connection #1..N: upload/download
```

Каждый upload chunk несёт:

```go
type UploadChunk struct {
    UploadID [16]byte
    Offset   uint64
    Data     []byte
}
```

Правила:

- `Offset` должен быть равен текущему `received_bytes`;
- повтор последнего полностью записанного чанка допускается только после
  специального status/resume ответа, не «угадывается» сервером;
- размер data не превышает negotiated ChunkSize;
- после записи chunk staging-файл не обязан fsync-иться каждый раз;
- `received_bytes` сохраняется не реже заданного checkpoint interval;
- перед resume сервер сверяет checkpoint с фактическим размером staging-файла;
- меньший безопасный offset побеждает, лишний хвост truncate-ится.

### 8.4. Commit

Клиент отправляет `UPLOAD_COMMIT`. Сервер:

1. переводит state в `verifying`;
2. проверяет фактический размер;
3. вычисляет checksum с context cancellation;
4. сравнивает expected checksum, если передан;
5. берёт keyed lock целевого parent/name;
6. повторно проверяет conflict;
7. создаёт version старого файла, если overwrite;
8. публикует staging;
9. transaction:
   - upsert resource;
   - increment revision;
   - `used_bytes += delta`;
   - `reserved_bytes -= reservation`;
   - upload completed;
   - append change;
10. отправляет `UPLOAD_DONE`;
11. broadcast EVENT_FS.

При checksum mismatch staging удаляется, reservation освобождается, state
становится failed.

### 8.5. Cancel и expiration

`UPLOAD_CANCEL` идемпотентен.

Cleaner:

- раз в configured interval выбирает expired uploads;
- пытается перевести их в `expired` compare-and-swap update;
- удаляет staging;
- освобождает reservation;
- пишет audit event.

### 8.6. Server disk full

Перед Begin выполняется advisory free-space check, но окончательной гарантии он
не даёт. `ENOSPC` во время записи:

- upload переводится в failed;
- connection остаётся синхронизированным, если можно отправить terminal response;
- staging удаляется или сохраняется ограниченное время для диагностики согласно
  config;
- reservation освобождается;
- возвращается отдельный `DISK_FULL`, а не `INTERNAL_ERROR`.

---

## 9. Мутации файловой системы

### 9.1. Общие правила

Каждая мутация:

- принимает RequestID;
- проверяет права до начала I/O;
- берёт keyed locks в детерминированном порядке;
- использует ResourceID, а путь разрешает только один раз в transaction snapshot;
- создаёт durable change journal entry;
- публикует EVENT только после commit;
- возвращает новое состояние ресурса;
- имеет explicit conflict policy.

### 9.2. MKDIR

```text
MKDIR(path, parents=false)
```

- без `parents` существующий родитель обязателен;
- с `parents` создаётся цепочка;
- повтор с тем же RequestID возвращает прежний result;
- существующий каталог может считаться success только при `exist_ok=true`;
- существующий файл — conflict.

### 9.3. MOVE/RENAME

```text
MOVE(source, destination, overwrite=false)
```

- внутри одного volume используется atomic rename;
- каталог нельзя переместить внутрь самого себя;
- при overwrite старый target уходит в versions/trash согласно policy;
- ResourceID сохраняется;
- descendants не получают новые ID;
- change содержит old_path и path;
- locks берутся по отсортированным ResourceID/parent keys во избежание deadlock.

### 9.4. COPY

На M13 допустимо byte-copy во временный файл с последующим publish.

Требования:

- копирование context-aware;
- квота резервируется по размеру;
- копия получает новый ResourceID и revision=1;
- partial copy не виден;
- копирование каталога рекурсивно и либо полностью успешно, либо откатывается;
- для очень больших деревьев операция может стать background job в M18.

### 9.5. DELETE

По умолчанию DELETE означает move to trash.

Опции:

```text
recursive
permanent
expected_revision
```

- удаление непустого каталога без recursive отклоняется;
- permanent требует повышенного подтверждения в TUI;
- expected_revision предотвращает удаление уже изменённого файла;
- публичные links ресурса отзываются;
- quota по умолчанию освобождается только после permanent purge либо согласно
  явно выбранной политике. Для первой версии trash продолжает занимать квоту,
  чтобы удалением нельзя было обходить storage accounting.

### 9.6. Optimistic concurrency

Мутации существующего файла принимают необязательный `ExpectedRevision`.

Если текущая revision отличается, сервер возвращает `REVISION_CONFLICT` с
текущими метаданными. TUI предлагает refresh/retry; sync-клиент создаёт conflict
copy.

---

## 10. Корзина

### 10.1. Поведение

Удалённый объект:

- исчезает из обычного дерева;
- сохраняет ResourceID;
- получает TrashID;
- хранит original parent/name;
- доступен только владельцу и admin;
- автоматически purge-ится после retention;
- может быть восстановлен в исходное или новое место.

### 10.2. Restore conflicts

Если исходное имя занято:

- default: reject conflict;
- `--rename`: сервер выбирает безопасное имя;
- `--overwrite`: требует ExpectedRevision/подтверждение;
- restore каталога восстанавливает поддерево.

### 10.3. Purge

Purge:

1. блокирует resource;
2. удаляет current content и versions по policy;
3. уменьшает used_bytes;
4. удаляет metadata;
5. пишет tombstone change;
6. удаляет physical files;
7. при ошибке physical delete оставляет cleanup job, но не возвращает объект в
   обычный namespace.

---

## 11. История версий

### 11.1. Когда создаётся версия

Предыдущая revision сохраняется при:

- upload overwrite;
- copy overwrite;
- restore over existing;
- sync update;
- явной server-side замене содержимого.

Rename/move без изменения содержимого не создаёт content version, но пишет
journal change.

### 11.2. API

```text
VERSION_LIST(path)
VERSION_RESTORE(path, revision, mode)
VERSION_DOWNLOAD(path, revision)
VERSION_DELETE(path, revision)
```

Restore старой версии создаёт **новую текущую revision**, а не перематывает
номер назад.

### 11.3. Retention

Config:

```json
{
  "versions": {
    "enabled": true,
    "retention_days": 30,
    "max_versions_per_file": 20
  }
}
```

Cleaner сначала применяет max count, затем age. Удаление version уменьшает
used_bytes. Активно скачиваемая версия защищена lease/refcount.

---

## 12. Download improvements

Существующий download/resume сохраняется, но v3 добавляет:

- ResourceID и Revision в accept/done;
- `ExpectedRevision` в request;
- отдельные transfer connections;
- checksum всегда соответствует конкретной revision;
- возможность скачать старую version;
- понятный `RESOURCE_CHANGED` при изменении во время передачи.

Сервер должен открыть file descriptor и stat один раз. Передача читает именно
открытый inode/handle. В конце сервер сообщает revision, которую реально отдал.

### 12.1. Parallel downloads

Клиентский pool ограничен:

```text
min(server max, client config, 8)
```

Один файл сначала качается одним потоком. Multipart одного файла откладывается до
профилирования: он усложняет checksum, sparse files и fairness rate limiter.

---

## 13. Пагинация и большие каталоги

Текущий ответ целиком ограничен MaxControlPayload. В v3 листинг обязателен с
пагинацией:

```go
type ListRequest struct {
    Path      string
    PageSize  uint32
    PageToken string
    Sort      uint8
}
```

```go
type ListResponse struct {
    Path          string
    Entries       []Entry
    NextPageToken string
    SnapshotID    string
}
```

Требования:

- server clamps PageSize;
- page token подписан HMAC и непрозрачен;
- token включает directory ResourceID, sort, cursor и snapshot/version marker;
- изменившийся каталог может вернуть `PAGE_SNAPSHOT_EXPIRED`;
- клиент перезапускает listing;
- TUI подгружает страницы лениво;
- batch `list --all` обходит все страницы с upper limit.

---

## 14. Durable change journal

`fsnotify` остаётся ускорителем live UI, но не гарантией доставки.

Каждая успешно committed мутация записывает `changes` в той же SQLite
transaction, что и metadata.

### 14.1. API

```text
CHANGES_GET(cursor, limit)
CHANGES_RESPONSE(items, next_cursor, has_more, baseline_id)
```

Cursor — opaque signed token или ChangeSeq.

Изменения:

```go
type Change struct {
    Seq        uint64
    Operation  string
    ResourceID string
    Path       string
    OldPath    string
    Revision   uint64
    Kind       string
    Timestamp  int64
}
```

### 14.2. Tombstones

Delete/purge обязательно оставляет tombstone в journal, иначе офлайн sync-клиент
не узнает об удалении.

### 14.3. Journal compaction

После retention старые changes могут удаляться только при наличии baseline
snapshot. Клиент со слишком старым cursor получает `CURSOR_EXPIRED` и выполняет
полный reconcile.

---

## 15. `fshare-sync`: двусторонняя синхронизация

### 15.1. Назначение

`fshare-sync` синхронизирует выбранный локальный каталог с удалённым `/home/...`.
Он не встроен в TUI, чтобы долгоживущий daemon и интерактивный UI имели разные
жизненные циклы.

### 15.2. Локальная БД

В корне sync state или config dir:

```sql
CREATE TABLE sync_entries (
    local_relpath       TEXT PRIMARY KEY,
    resource_id         TEXT,
    remote_revision     INTEGER,
    local_size          INTEGER,
    local_mtime_ns      INTEGER,
    local_checksum      BLOB,
    base_checksum       BLOB,
    state               TEXT,
    last_seen_seq       INTEGER
);
```

Также хранится remote cursor, profile, remote root и ignore rules.

### 15.3. Начальный reconcile

1. полный локальный scan;
2. paginated remote scan;
3. сопоставление прежде всего по ResourceID, затем по пути;
4. определение create/update/delete/conflict;
5. построение плана;
6. печать dry-run по флагу;
7. выполнение с bounded parallelism;
8. commit локального cursor только после успешной обработки batch.

### 15.4. Обычный цикл

- локальный watcher только будит scan, но не является источником истины;
- remote changes читаются по cursor;
- периодический full lightweight scan ловит пропущенные локальные события;
- операции повторяются с exponential backoff;
- auth/revision conflicts не ретраятся бесконечно.

### 15.5. Conflict algorithm

Используется three-way comparison:

```text
base = состояние после последней успешной синхронизации
local = текущее локальное
remote = текущая remote revision
```

- изменился только local → upload;
- изменился только remote → download;
- оба равны base → no-op;
- оба изменились одинаково по checksum → metadata update;
- оба изменились по-разному → conflict.

Conflict copy:

```text
filename (conflict <hostname> <YYYY-MM-DD HHMMSS>).ext
```

Ни одна сторона молча не затирается.

### 15.6. Deletes

Удаление распространяется только если существует база предыдущего состояния.
Первый scan никогда не считает отсутствие файла намеренным delete без explicit
режима.

### 15.7. Ignore rules

Поддерживаются:

- glob patterns;
- `.fshareignore`;
- max file size;
- symlink policy;
- hidden files;
- include/exclude remote subtrees.

---

## 16. TLS и доверие серверу

### 16.1. Сервер

Используется `crypto/tls`.

Config:

```json
{
  "tls": {
    "enabled": true,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key",
    "min_version": "1.3",
    "require": true
  }
}
```

По умолчанию production config требует TLS. Plain TCP допускается только
loopback или explicit `--insecure`.

### 16.2. Клиент

Режимы доверия:

1. system CA;
2. custom CA file;
3. TOFU fingerprint;
4. insecure skip verify — только explicit dev flag с предупреждением.

Профиль хранит:

```go
TLSMode
CAFile
PinnedSPKIHash
```

При первом TOFU-подключении пользователь подтверждает fingerprint. При смене
fingerprint соединение блокируется до explicit re-pin.

### 16.3. Session resumption

После M14 можно добавить короткоживущий session token для transfer connections.
Token:

- случайный;
- привязан к UserID и основной session;
- имеет TTL;
- хранится сервером как hash;
- отзывается при logout/kick/disable;
- передаётся только по TLS.

Пароль или proof не повторяются на каждом transfer connection.

---

## 17. Публичные ссылки и HTTPS gateway

### 17.1. Почему отдельный gateway

Получатель ссылки не обязан устанавливать console client. Поэтому нужен обычный
HTTPS endpoint.

`fshare-gateway` может работать:

- в том же процессе по отдельному HTTP listener;
- отдельным бинарём с доступом к metadata/storage.

Для первой версии предпочтителен отдельный package, но один process mode
допустим.

### 17.2. Создание ссылки

```text
share create <path> [--expires 7d] [--password] [--no-download]
share list
share revoke <id>
```

Сервер генерирует 256-bit random token. В БД хранит SHA-256 token.

URL:

```text
https://host/s/<token>
```

### 17.3. HTTP endpoints

```text
GET  /s/{token}             metadata or minimal HTML
GET  /s/{token}/download    streamed download
POST /s/{token}/unlock      password exchange
```

Требования:

- constant-time token hash compare;
- rate limit по IP и share ID;
- expiry/revocation;
- optional password via memory-hard password hash;
- Content-Disposition с безопасным filename;
- Range support для resume;
- no directory traversal;
- security headers;
- audit access без полного token;
- directory share на первом этапе отдаёт zip stream либо disabled согласно
  capability.

---

## 18. TUI и batch CLI

### 18.1. Направление операций

Активная панель определяет source, другая — destination:

- remote -> local: download;
- local -> remote: upload;
- remote -> remote: server-side copy/move;
- local -> local: обычная локальная операция с подтверждением.

### 18.2. Горячие клавиши

```text
F5   copy/upload/download
F6   move/rename
F7   mkdir
F8   delete to trash
F9   admin panel
F10  quit
Ctrl+R refresh
Ctrl+T trash
Ctrl+V versions
Ctrl+S shares
```

Разрушающие операции показывают modal с точным target и количеством объектов.

### 18.3. Command mode

```text
put <local...> [remote-dir]
get <remote...> [local-dir]
mkdir [-p] <remote-path>
mv <src> <dst>
cp <src> <dst>
rm [-r] [--permanent] <path...>
trash list
trash restore <id> [dst]
trash purge <id>
versions <path>
restore-version <path> <revision>
quota
share create|list|revoke ...
sync status
```

### 18.4. Batch flags

Существующий `--batch` расширяется или заменяется subcommands. Предпочтительная
форма:

```text
fshare-commander list /
fshare-commander get /a.bin --out a.bin
fshare-commander put ./a.bin --to /home/a.bin
fshare-commander mkdir /home/docs
fshare-commander rm /home/old.bin
fshare-commander quota
```

До миграции старые flags продолжают работать с deprecation warning.

### 18.5. Transfer queue

Очередь должна показывать:

- direction;
- source/destination;
- state;
- bytes;
- speed;
- ETA;
- retry count;
- pause/cancel;
- resumable status.

Перезапуск TUI не обязан сохранять очередь на M13, но `.part/.upart` позволяют
продолжить передачу вручную. Persistent queue — M18.

---

## 19. Конфигурация

Новые секции:

```json
{
  "database": {
    "path": "metadata.db",
    "busy_timeout_ms": 5000
  },
  "storage": {
    "data_root": "./data",
    "min_free_bytes": 1073741824
  },
  "uploads": {
    "ttl_hours": 24,
    "checkpoint_bytes": 8388608,
    "max_parallel_per_user": 4
  },
  "trash": {
    "retention_days": 30
  },
  "versions": {
    "enabled": true,
    "retention_days": 30,
    "max_versions_per_file": 20
  },
  "changes": {
    "retention_days": 90,
    "page_size": 1000
  },
  "tls": {
    "enabled": true,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key",
    "require": true
  },
  "gateway": {
    "enabled": false,
    "listen": ":8443",
    "base_url": ""
  }
}
```

Каждый ключ отмечается как hot или restart-only. Изменение storage/database/TLS
path — restart-only. Лимиты, retention и rate limits могут быть hot, если
сервис действительно читает snapshot на каждой операции.

---

## 20. Логи, аудит и метрики

### 20.1. Structured logging

Поля:

```text
request_id
session_id
user_id
operation
resource_id
path_hash or safe_path
upload_id
bytes
duration_ms
result
error_code
remote_ip
```

Полный публичный token, пароль, proof, StoredKey и session token запрещены.

### 20.2. Audit log

Неизменяемые audit records для:

- login success/failure/ban;
- user create/disable/role/quota;
- share create/revoke/access;
- permanent delete/purge;
- restore version/trash;
- admin config;
- kick/shutdown.

Audit может храниться в SQLite и экспортироваться JSONL.

### 20.3. Метрики

Минимум:

- active sessions;
- active uploads/downloads;
- bytes uploaded/downloaded;
- upload failures by reason;
- quota used/reserved;
- staging bytes;
- trash/version bytes;
- DB transaction latency;
- journal lag;
- sync conflicts;
- HTTP share requests.

Экспорт Prometheus optional, admin stats обязателен.

---

## 21. Backup, restore и миграции

### 21.1. Backup

Команда:

```text
fshare-daemon --backup <dir>
```

Должна:

1. остановить новые мутации или создать consistent snapshot;
2. выполнить SQLite online backup;
3. сохранить manifest;
4. при необходимости snapshot/hardlink файлов;
5. проверить checksums manifest.

Для первой версии допустима documented остановка daemon перед filesystem backup,
но metadata backup должен быть корректным.

### 21.2. Restore

Restore работает только при остановленном daemon:

- проверяет manifest;
- проверяет schema compatibility;
- восстанавливает metadata и data;
- запускает reconciliation dry-run;
- требует explicit `--apply`.

### 21.3. Миграция users.json

M12 предоставляет one-shot:

```text
fshare-daemon --migrate-users users.json
```

- создаёт SQLite DB;
- импортирует login/role/stored_key/enabled;
- устанавливает per-user auth_iters из старого config;
- не удаляет исходный JSON;
- повторный запуск идемпотентен;
- конфликт логина завершается понятной ошибкой.

---

## 22. Ошибки протокола v3

Новые коды:

```text
QUOTA_EXCEEDED
DISK_FULL
RESOURCE_EXISTS
RESOURCE_CHANGED
REVISION_CONFLICT
UPLOAD_NOT_FOUND
UPLOAD_EXPIRED
OFFSET_MISMATCH
CHECKSUM_MISMATCH
DIRECTORY_NOT_EMPTY
INVALID_NAME
CURSOR_EXPIRED
PAGE_SNAPSHOT_EXPIRED
SHARE_EXPIRED
SHARE_REVOKED
TLS_REQUIRED
FEATURE_UNSUPPORTED
OPERATION_IN_PROGRESS
```

Error response содержит:

```go
type ErrorV3 struct {
    RequestID uint64
    Code      uint16
    Retryable bool
    Message   string
    Details   map[string]string // bounded and allowlisted
}
```

`Message` предназначен человеку, логика клиента строится только по Code.

---

## 23. Конкурентность и блокировки

### 23.1. Keyed locks

Нужен bounded keyed-lock manager:

```go
Lock(keys ...string) func()
```

- keys сортируются;
- refcount удаляет неиспользуемые mutex;
- ожидание context-aware;
- lock не удерживается во время медленной сетевой передачи;
- lock удерживается на короткой commit/mutation фазе.

### 23.2. DB transactions

Не держать write transaction во время:

- загрузки чанков;
- checksum большого файла;
- копирования больших данных;
- HTTP download.

Использовать prepare/IO/commit pattern с повторной проверкой revision.

### 23.3. Outgoing queues

Текущая per-session writer queue сохраняется. Для transfer connection
data frames могут иметь отдельную bounded queue или писаться единственным owner
goroutine. Медленный клиент не блокирует broadcast другим.

---

## 24. Тестирование

### 24.1. Unit tests

Обязательны:

- v3 codecs and malformed frames;
- path/name validation;
- quota arithmetic;
- state transitions;
- conflict rules;
- signed page tokens;
- share token hashing;
- cursor encoding;
- keyed lock cleanup;
- migration parsing.

### 24.2. Integration tests

С реальным daemon на временном data root:

1. user isolation;
2. upload/download round-trip;
3. resume after disconnect;
4. cancel before/after UploadAccept;
5. two uploads competing for quota;
6. two uploads targeting same path;
7. overwrite creates version;
8. delete/restore/purge;
9. move directory with descendants;
10. pagination while directory changes;
11. TLS good/bad/pin changed;
12. disabled user sessions are dropped;
13. journal cursor after offline period;
14. public link expiry/password/range;
15. sync conflict copy;
16. server restart with active staging;
17. recovery after injected crash in each publish phase.

### 24.3. Race and fuzz

CI:

```text
go test ./...
go test -race ./...
go vet ./...
go test -fuzz ...  (scheduled or bounded)
```

Fuzz targets:

- frame decoder;
- every v3 message decoder;
- path cleaner;
- page/cursor token parser;
- recovery record parser;
- config and migration parser.

### 24.4. Fault injection

В `storage` вводятся test hooks:

```go
type FaultPoint string
```

Тест может вернуть ошибку или вызвать simulated crash после:

- staging sync;
- version move;
- final rename;
- DB commit;
- quota update;
- journal append;
- marker removal.

После нового запуска reconciliation должен восстановить инварианты.

### 24.5. Load tests

Сценарии:

- 200 idle sessions;
- 20 parallel downloads;
- 20 parallel uploads;
- mixed 70/30 read/write;
- directory with 1M entries through paging;
- journal polling by 100 clients;
- slow client event queue;
- quota cleaner and version cleaner under load.

Снимаются CPU, allocations, open FDs, DB latency и fairness rate limiter.

---

## 25. Этапы реализации

## M12 — Пользователи как система

### Scope

- SQLite and migrations;
- UserID, per-user auth_iters;
- user admin API/CLI;
- secure bootstrap;
- `/home` and `/public`;
- separate `os.Root`;
- event visibility filtering;
- users.json migration.

### Definition of Done

- два пользователя не видят home друг друга листингом, stat, checksum, прямым
  путём, событием или journal;
- disabled user cannot create new session, existing sessions are dropped;
- empty DB cannot start insecurely without explicit flag;
- migration preserves authentication;
- all tests pass with race detector.

## M13 — Upload, mutations and quotas

### Scope

- v3 negotiation;
- transfer connections/session tokens;
- resumable upload;
- quota reservation;
- mkdir/move/copy/delete;
- TUI F5/F6/F7/F8;
- batch put/mkdir/mv/cp/rm;
- paginated listing.

### Definition of Done

- 10+ GiB upload resumes after client/server restart;
- oversize upload rejected before bytes are accepted;
- parallel reservations never exceed quota;
- no partial file appears in list;
- upload, move and delete survive injected faults;
- remote panel supports full CRUD.

## M14 — TLS and production hardening

### Scope

- TLS 1.3;
- system/custom CA and TOFU;
- profile pin;
- TLS-required mode;
- hardened Docker init;
- transfer session tokens;
- secret-safe logging.

### Definition of Done

- packet capture shows no login/file content;
- changed certificate blocks TOFU client;
- no-auth mode requires explicit flag;
- all public listeners have deadlines and connection limits.

## M15 — Trash, versions and durable recovery

### Scope

- trash API/TUI;
- versions API/TUI;
- retention cleaners;
- recovery markers;
- startup reconciliation;
- backup/restore baseline;
- audit expansion.

### Definition of Done

- delete/restore works for file and tree;
- overwrite creates downloadable/restorable version;
- injected crash at every publish phase recovers;
- quota remains correct after restore/purge/cleanup;
- M15 qualifies as cloud-drive MVP.

## M16 — Public links and ACL

### Scope

- shares DB/service;
- HTTPS gateway;
- password/expiry/revoke/no-download;
- Range download;
- public ACL;
- admin/share audit.

### Definition of Done

- untrusted recipient downloads through browser/curl without client;
- expired/revoked token cannot access bytes;
- token is not stored or logged in plaintext;
- ACL affects list/stat/download/events consistently.

## M17 — Change journal and sync client

### Scope

- durable journal/cursors/tombstones;
- baseline and cursor expiry;
- `fshare-sync`;
- local state DB;
- ignore rules;
- three-way conflict handling;
- daemon/service mode.

### Definition of Done

- client offline for days catches up without missed deletes;
- simultaneous edits produce conflict copy, not silent loss;
- cursor commit is crash-safe;
- full reconcile restores consistency after cursor expiry.

## M18 — Scale, UX and operations

### Scope

- persistent transfer queue;
- background copy jobs;
- search/metadata index;
- Prometheus endpoint;
- admin DB maintenance;
- journal/version compaction;
- performance tuning;
- packaging/systemd/installers.

### Definition of Done

- documented install/upgrade/backup/restore;
- load targets pass without unbounded memory/maps/goroutines;
- million-entry directory remains usable through paging/search;
- release artifacts produced for Linux/Windows/macOS.

---

## 26. Рекомендуемый порядок PR внутри этапов

Каждый этап разбивается на небольшие вертикальные PR:

1. ADR + domain types + schema migration;
2. metadata repositories with tests;
3. service API and invariants;
4. proto messages/codecs;
5. server handlers;
6. client methods;
7. TUI/batch surface;
8. integration/fault tests;
9. docs/config/examples;
10. hardening review.

Нельзя сначала добавить все wire messages без рабочего consumer. Каждый PR после
foundation должен завершать хотя бы один сквозной сценарий.

Пример M13:

```text
PR1 quota repository + reserve/release tests
PR2 upload begin + staging + one-shot small upload
PR3 chunking and resume
PR4 atomic commit + recovery
PR5 TUI put and transfer queue
PR6 mkdir/move/delete
PR7 copy and directory operations
PR8 paging
PR9 adversarial/fault/load hardening
```

---

## 27. Изменения публичных Go API

Предварительные интерфейсы:

```go
type UserService interface {
    Authenticate(login string, proof []byte) (User, error)
    Create(ctx context.Context, in CreateUser) (User, error)
    Disable(ctx context.Context, userID int64) error
    SetQuota(ctx context.Context, userID int64, quota uint64) error
    Quota(ctx context.Context, userID int64) (Quota, error)
}

type UploadService interface {
    Begin(ctx context.Context, user User, req BeginUpload) (UploadSession, error)
    Status(ctx context.Context, user User, uploadID string) (UploadSession, error)
    WriteChunk(ctx context.Context, user User, uploadID string, offset uint64, data []byte) error
    Commit(ctx context.Context, user User, uploadID string) (Resource, error)
    Cancel(ctx context.Context, user User, uploadID string) error
}

type FileService interface {
    List(ctx context.Context, user User, req ListRequest) (ListPage, error)
    Stat(ctx context.Context, user User, path string) (Resource, error)
    Mkdir(ctx context.Context, user User, req MkdirRequest) (Resource, error)
    Move(ctx context.Context, user User, req MoveRequest) (Resource, error)
    Copy(ctx context.Context, user User, req CopyRequest) (Resource, error)
    Delete(ctx context.Context, user User, req DeleteRequest) (TrashEntry, error)
}

type ChangeService interface {
    AppendTx(ctx context.Context, tx Tx, change Change) error
    Get(ctx context.Context, user User, cursor string, limit int) (ChangePage, error)
}
```

Конкретные структуры уточняются в коде, но границы ответственности сохраняются.

---

## 28. Acceptance checklist итогового продукта

Перед объявлением проекта «консольным аналогом облачного диска» должны быть
выполнены все пункты:

### Безопасность

- [ ] TLS включён по умолчанию;
- [ ] нет неявного anonymous admin;
- [ ] user roots физически изолированы;
- [ ] public tokens хэшируются;
- [ ] secrets отсутствуют в логах;
- [ ] malformed input изолирован одной сессией.

### Целостность

- [ ] upload атомарен;
- [ ] checksum проверяется;
- [ ] resume работает после обрыва;
- [ ] quota transaction-safe;
- [ ] recovery проходит после injected crash;
- [ ] backup/restore документированы и протестированы.

### Функциональность

- [ ] upload/download;
- [ ] mkdir/copy/move/delete;
- [ ] trash;
- [ ] versions;
- [ ] public links;
- [ ] paginated listing;
- [ ] sync journal;
- [ ] two-way sync;
- [ ] admin users/quotas.

### Эксплуатация

- [ ] CI Linux/Windows/macOS;
- [ ] race detector;
- [ ] migrations;
- [ ] Docker secure init;
- [ ] systemd example;
- [ ] metrics and audit;
- [ ] release/upgrade guide.

---

## 29. Решения по умолчанию, чтобы не блокировать разработку

Если отдельный ADR не изменит решение, используются следующие defaults:

1. v2 не меняется; cloud API — v3.
2. SQLite WAL, pure-Go driver.
3. Один daemon node и локальная filesystem.
4. UserID/ResourceID стабильны, путь не является ID.
5. Upload staging находится на том же filesystem, что и live data.
6. Delete идёт в trash; trash занимает квоту до purge.
7. Restore version создаёт новую revision.
8. Control и transfer connections разделены.
9. TLS 1.3 включён по умолчанию.
10. Sync использует journal + периодический reconcile, не один fsnotify.
11. Conflict никогда не разрешается silent overwrite.
12. Public gateway хранит только hash token.
13. Любая операция, которая может оставить split-brain между SQLite и FS,
    использует recovery marker и fault-injection tests.
14. Оптимизация не принимается ценой нарушения этих инвариантов.

---

## 30. Первый практический шаг

Начинать реализацию следует с M12 foundation:

1. создать `internal/metadata`;
2. выбрать и зафиксировать SQLite driver;
3. добавить migration `0001_users_resources`;
4. импортировать users.json;
5. ввести `UserID` и `UserContext`;
6. открыть отдельный `os.Root` на home пользователя;
7. изменить v3 list/stat/download так, чтобы они работали через UserContext;
8. написать isolation integration test;
9. только после этого начинать upload.

Такой порядок не даёт построить upload поверх старой модели общего share root,
которую затем пришлось бы переписывать.
