-- Миграция 0001 — ВСЯ схема раздела 6 docs/tz/10-cloud-drive-spec.md.
--
-- Таблицы создаются одной миграцией, включая те, что начинают наполняться на
-- более поздних этапах (uploads, versions, trash_entries, changes,
-- journal_state, shares, audit_events, blob_gc): §25 прямо запрещает добавлять
-- колонки вторым проходом. Причина не в аккуратности, а в STRICT: добавить его
-- существующей таблице ALTER TABLE не умеет, и задним числом это пересоздание
-- таблицы с копированием данных (ADR 0001 §5.4 п. 2).
--
-- Все таблицы объявлены STRICT. Без него запрет §6.1 «все timestamps — INTEGER,
-- RFC3339 в базе не хранится нигде» не имеет механического обеспечения:
-- случайно забинденный time.Time молча ложится TEXT-строкой в INTEGER-колонку
-- _ms из-за type affinity обычных rowid-таблиц. STRICT такую вставку отклоняет.
--
-- Порядок создания — по зависимостям внешних ключей (§6.11), чтобы схему можно
-- было читать сверху вниз.

-- ─── §6.2 users ──────────────────────────────────────────────────────────────

CREATE TABLE users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    login                TEXT NOT NULL UNIQUE,
    role                 TEXT NOT NULL CHECK (role IN ('user','admin')),
    state                TEXT NOT NULL DEFAULT 'active'
                              CHECK (state IN ('active','disabled','pending_delete')),
    kdf_algo             TEXT NOT NULL DEFAULT 'pbkdf2-sha256'
                              CHECK (kdf_algo IN ('pbkdf2-sha256','argon2id')),
    salt                 BLOB NOT NULL,
    stored_key           BLOB NOT NULL,
    auth_iters           INTEGER NOT NULL,
    kdf_params           TEXT,
    quota_bytes          INTEGER NOT NULL DEFAULT 0,
    used_bytes           INTEGER NOT NULL DEFAULT 0,
    reserved_bytes       INTEGER NOT NULL DEFAULT 0,
    pending_delete_at_ms INTEGER,
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL,
    CHECK (id >= 0),
    CHECK ((state = 'pending_delete') = (pending_delete_at_ms IS NOT NULL))
) STRICT;

-- ─── §6.3 resources ──────────────────────────────────────────────────────────

CREATE TABLE resources (
    id                TEXT NOT NULL PRIMARY KEY,
    owner_user_id     INTEGER NOT NULL,
    parent_id         TEXT NOT NULL,
    namespace         TEXT NOT NULL CHECK (namespace IN ('home','public')),
    name              TEXT NOT NULL,
    name_fold         TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('file','dir')),
    current_revision  INTEGER NOT NULL DEFAULT 0,
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    checksum_algo     TEXT CHECK (checksum_algo IN ('crc32','sha256')),
    checksum          BLOB,
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL,
    deleted_at_ms     INTEGER,
    trashed_root_id   TEXT,
    FOREIGN KEY(owner_user_id)   REFERENCES users(id)     ON DELETE RESTRICT,
    FOREIGN KEY(parent_id)       REFERENCES resources(id) ON DELETE RESTRICT,
    FOREIGN KEY(trashed_root_id) REFERENCES resources(id) ON DELETE RESTRICT,
    CHECK ((deleted_at_ms IS NULL) = (trashed_root_id IS NULL)),
    CHECK (id <> parent_id OR kind = 'dir' OR deleted_at_ms IS NOT NULL),
    CHECK (name <> '' OR id = parent_id),
    CHECK (kind = 'file' OR size_bytes = 0)
) STRICT;

-- Уникальность имени задана ЧАСТИЧНЫМ индексом, а не table-constraint: в SQLite
-- NULL в уникальном ключе не конфликтуют, поэтому вариант с nullable-колонками
-- не действовал бы вовсе. Предикат WHERE deleted_at_ms IS NULL — это то, что
-- позволяет сценарию «удалил и залил заново» работать без ошибки (§10.1).
CREATE UNIQUE INDEX resources_uniq_name
    ON resources(namespace, parent_id, name)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_children
    ON resources(parent_id, name)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_children_kind
    ON resources(parent_id, kind, name)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_children_mtime
    ON resources(parent_id, updated_at_ms, id)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_children_size
    ON resources(parent_id, size_bytes, id)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_fold
    ON resources(namespace, parent_id, name_fold)
    WHERE deleted_at_ms IS NULL;

CREATE INDEX resources_trashed
    ON resources(owner_user_id, trashed_root_id)
    WHERE deleted_at_ms IS NOT NULL;

-- ─── §6.4 uploads ────────────────────────────────────────────────────────────

CREATE TABLE uploads (
    id                     TEXT NOT NULL PRIMARY KEY,
    user_id                INTEGER NOT NULL,
    client_upload_key      BLOB NOT NULL,
    target_parent_id       TEXT NOT NULL,
    target_name            TEXT NOT NULL,
    target_name_fold       TEXT NOT NULL,
    expected_size_bytes    INTEGER NOT NULL,
    expected_checksum_algo TEXT NOT NULL
                               CHECK (expected_checksum_algo IN ('crc32','sha256')),
    expected_checksum      BLOB NOT NULL,
    received_bytes         INTEGER NOT NULL DEFAULT 0,
    synced_bytes           INTEGER NOT NULL DEFAULT 0,
    reserved_bytes         INTEGER NOT NULL,
    overwrite_mode         TEXT NOT NULL
                               CHECK (overwrite_mode IN ('fail','overwrite')),
    state                  TEXT NOT NULL
                               CHECK (state IN ('created','receiving','verifying',
                                                'committing','completed','cancelled',
                                                'failed','expired')),
    staging_relpath        TEXT NOT NULL,
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL,
    expires_at_ms          INTEGER NOT NULL,
    FOREIGN KEY(user_id)          REFERENCES users(id)     ON DELETE RESTRICT,
    FOREIGN KEY(target_parent_id) REFERENCES resources(id) ON DELETE RESTRICT,
    CHECK (synced_bytes <= received_bytes),
    CHECK (received_bytes <= expected_size_bytes)
) STRICT;

-- Механизм инварианта 7 (§2.2): два параллельных UploadBegin после reconnect не
-- создадут двух резервирований.
CREATE UNIQUE INDEX uploads_client_key
    ON uploads(user_id, client_upload_key)
    WHERE state IN ('created','receiving','verifying','committing');

-- Исход гонки двух UPLOAD_BEGIN в одно имя определяет СУБД, а не порядок
-- проверок в коде. Индекс построен по свёрнутому имени: иначе Report.pdf и
-- report.pdf считались бы разными целями (§6.4).
CREATE UNIQUE INDEX uploads_active_target
    ON uploads(target_parent_id, target_name_fold)
    WHERE state IN ('created','receiving','verifying','committing');

CREATE INDEX uploads_expiry ON uploads(state, expires_at_ms);

CREATE INDEX uploads_retention ON uploads(state, updated_at_ms);

-- ─── §6.5 versions ───────────────────────────────────────────────────────────

CREATE TABLE versions (
    resource_id       TEXT NOT NULL,
    revision          INTEGER NOT NULL,
    owner_user_id     INTEGER NOT NULL,
    size_bytes        INTEGER NOT NULL,
    checksum_algo     TEXT NOT NULL CHECK (checksum_algo IN ('crc32','sha256')),
    checksum          BLOB NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    expires_at_ms     INTEGER,
    PRIMARY KEY(resource_id, revision),
    FOREIGN KEY(resource_id)   REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY(owner_user_id) REFERENCES users(id)     ON DELETE RESTRICT
) STRICT;

CREATE INDEX versions_expiry ON versions(expires_at_ms);
CREATE INDEX versions_owner  ON versions(owner_user_id);

-- ─── §6.6 trash_entries ──────────────────────────────────────────────────────

CREATE TABLE trash_entries (
    id                 TEXT NOT NULL PRIMARY KEY,
    user_id            INTEGER NOT NULL,
    resource_id        TEXT NOT NULL UNIQUE,
    namespace          TEXT NOT NULL CHECK (namespace IN ('home','public')),
    kind               TEXT NOT NULL CHECK (kind IN ('file','dir')),
    original_parent_id TEXT,
    original_name      TEXT NOT NULL,
    original_path      TEXT NOT NULL,
    subtree_bytes      INTEGER NOT NULL,
    subtree_entries    INTEGER NOT NULL,
    deleted_at_ms      INTEGER NOT NULL,
    expires_at_ms      INTEGER NOT NULL,
    FOREIGN KEY(user_id)            REFERENCES users(id)     ON DELETE RESTRICT,
    FOREIGN KEY(resource_id)        REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY(original_parent_id) REFERENCES resources(id) ON DELETE SET NULL
) STRICT;

CREATE INDEX trash_expiry ON trash_entries(expires_at_ms);
CREATE INDEX trash_user   ON trash_entries(user_id, deleted_at_ms);

-- ─── §6.7 changes и journal_state ────────────────────────────────────────────

-- Внешнего ключа на resources(id) здесь нет сознательно: запись журнала обязана
-- пережить удаление ресурса, иначе tombstone исчезнет вместе с объектом,
-- который он описывает.
CREATE TABLE changes (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER,
    namespace         TEXT NOT NULL CHECK (namespace IN ('home','public')),
    resource_id       TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('file','dir')),
    operation         TEXT NOT NULL CHECK (operation IN ('create','update','mkdir',
                                                         'move','trash','restore_trash',
                                                         'purge','version_restore')),
    path              TEXT NOT NULL,
    old_path          TEXT,
    revision          INTEGER NOT NULL,
    size_bytes        INTEGER,
    checksum_algo     TEXT CHECK (checksum_algo IN ('crc32','sha256')),
    checksum          BLOB,
    actor_user_id     INTEGER,
    actor_client_id   TEXT,
    created_at_ms     INTEGER NOT NULL,
    CHECK (namespace <> 'public' OR user_id IS NULL OR operation = 'trash')
) STRICT;

CREATE INDEX changes_user_seq ON changes(user_id, seq);
CREATE INDEX changes_ns_seq   ON changes(namespace, seq);

CREATE TABLE journal_state (
    user_id                INTEGER PRIMARY KEY,
    min_retained_seq       INTEGER NOT NULL,
    baseline_id            TEXT NOT NULL,
    baseline_seq           INTEGER NOT NULL,
    baseline_created_at_ms INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;

-- ─── §6.8 shares ─────────────────────────────────────────────────────────────

CREATE TABLE shares (
    id                  TEXT NOT NULL PRIMARY KEY,
    owner_user_id       INTEGER NOT NULL,
    resource_id         TEXT NOT NULL,
    token_hash          BLOB NOT NULL UNIQUE,
    password_phc        TEXT,
    allow_download      INTEGER NOT NULL DEFAULT 1,
    state               TEXT NOT NULL DEFAULT 'active'
                            CHECK (state IN ('active','suspended','revoked')),
    expires_at_ms       INTEGER,
    suspended_at_ms     INTEGER,
    revoked_at_ms       INTEGER,
    created_at_ms       INTEGER NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id)     ON DELETE RESTRICT,
    FOREIGN KEY(resource_id)   REFERENCES resources(id) ON DELETE CASCADE,
    CHECK ((state = 'revoked')   = (revoked_at_ms IS NOT NULL)),
    CHECK ((state = 'suspended') = (suspended_at_ms IS NOT NULL))
) STRICT;

CREATE INDEX shares_owner    ON shares(owner_user_id, state);
CREATE INDEX shares_resource ON shares(resource_id);
CREATE INDEX shares_expiry   ON shares(expires_at_ms);

-- ─── §6.9 audit_events ───────────────────────────────────────────────────────

-- Внешнего ключа на users(id) нет намеренно: audit обязан пережить purge
-- актора, поэтому рядом с actor_user_id хранится actor_login на момент события.
CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms         INTEGER NOT NULL,
    actor_user_id INTEGER,
    actor_login   TEXT,
    remote_ip     TEXT,
    action        TEXT NOT NULL,
    subject_type  TEXT,
    subject_id    TEXT,
    result        TEXT NOT NULL CHECK (result IN ('ok','denied','error')),
    details_json  TEXT
) STRICT;

CREATE INDEX audit_ts        ON audit_events(ts_ms);
CREATE INDEX audit_actor_ts  ON audit_events(actor_user_id, ts_ms);
CREATE INDEX audit_action_ts ON audit_events(action, ts_ms);

-- ─── §6.10 blob_gc ───────────────────────────────────────────────────────────

-- Внешнего ключа на users(id) нет: очередь обязана пережить purge владельца,
-- owner_user_id информационен.
CREATE TABLE blob_gc (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_relpath    TEXT NOT NULL UNIQUE,
    size_bytes         INTEGER NOT NULL,
    owner_user_id      INTEGER,
    reason             TEXT NOT NULL CHECK (reason IN ('purge','version_expired',
                                                       'upload_expired','fsck',
                                                       'overwrite_source')),
    enqueued_at_ms     INTEGER NOT NULL,
    next_attempt_at_ms INTEGER NOT NULL,
    attempts           INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT
) STRICT;

CREATE INDEX blob_gc_due ON blob_gc(next_attempt_at_ms);

-- ─── §6.12 server_secrets ────────────────────────────────────────────────────

CREATE TABLE server_secrets (
    name          TEXT NOT NULL PRIMARY KEY
                       CHECK (name IN ('page_token_key','server_secret')),
    value         BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    rotated_at_ms INTEGER,
    CHECK (length(value) = 32)
) STRICT;
