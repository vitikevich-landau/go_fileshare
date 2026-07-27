package metadata_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

const testAuthIters = 600_000

func testConfig(t *testing.T, dir string) db.Config {
	t.Helper()
	return db.Config{
		Path:          filepath.Join(dir, "metadata.db"),
		BusyTimeoutMs: 5000,
		Synchronous:   "NORMAL",
		ReadConns:     4,
	}
}

func open(t *testing.T, dir string) *db.DB {
	t.Helper()
	d, err := db.Open(context.Background(), testConfig(t, dir),
		metadata.Migrations(metadata.SeedParams{AuthIters: testAuthIters}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestSchemaObjects — миграция 0001 создаёт ВСЕ таблицы и индексы §6, включая
// те, что начинают наполняться на более поздних этапах: §25 запрещает добавлять
// их вторым проходом.
func TestSchemaObjects(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	wantTables := []string{
		"schema_migrations", // §6.1, создаётся runner'ом
		"users",             // §6.2
		"resources",         // §6.3
		"uploads",           // §6.4
		"versions",          // §6.5
		"trash_entries",     // §6.6
		"changes",           // §6.7
		"journal_state",     // §6.7
		"shares",            // §6.8
		"audit_events",      // §6.9
		"blob_gc",           // §6.10
		"server_secrets",    // §6.12
	}
	wantIndexes := []string{
		"resources_uniq_name", "resources_children", "resources_children_kind",
		"resources_children_mtime", "resources_children_size", "resources_fold",
		"resources_trashed",
		"uploads_client_key", "uploads_active_target", "uploads_expiry", "uploads_retention",
		"versions_expiry", "versions_owner",
		"trash_expiry", "trash_user",
		"changes_user_seq", "changes_ns_seq",
		"shares_owner", "shares_resource", "shares_expiry",
		"audit_ts", "audit_actor_ts", "audit_action_ts",
		"blob_gc_due",
	}

	have := func(kind string) map[string]bool {
		rows, err := d.Reader.QueryContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'`, kind)
		if err != nil {
			t.Fatalf("list %ss: %v", kind, err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out[name] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("list %ss: %v", kind, err)
		}
		return out
	}

	tables := have("table")
	for _, name := range wantTables {
		if !tables[name] {
			t.Errorf("table %s is missing", name)
		}
	}
	indexes := have("index")
	for _, name := range wantIndexes {
		if !indexes[name] {
			t.Errorf("index %s is missing", name)
		}
	}
}

// TestEveryTableIsStrict — §6.1 «все таблицы раздела 6 объявлены STRICT».
// Проверка механическая: без STRICT запрет «RFC3339 в базе не хранится нигде»
// не имеет обеспечения, а добавить STRICT задним числом ALTER TABLE не умеет.
func TestEveryTableIsStrict(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	rows, err := d.Reader.QueryContext(ctx, `
SELECT name FROM pragma_table_list
WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' AND strict = 0`)
	if err != nil {
		t.Fatalf("pragma_table_list: %v", err)
	}
	defer rows.Close()
	var loose []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		loose = append(loose, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("pragma_table_list: %v", err)
	}
	if len(loose) != 0 {
		t.Fatalf("tables declared without STRICT: %v", loose)
	}
}

// TestStrictRejectsTimeTime — та самая ошибка, ради которой §6.1 требует
// STRICT: случайно забинденный time.Time в INTEGER-колонку _ms. В обычной
// rowid-таблице он молча лёг бы TEXT-строкой.
func TestStrictRejectsTimeTime(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	_, err := d.Writer.ExecContext(ctx, `
INSERT INTO audit_events (ts_ms, action, result) VALUES (?, 'test', 'ok')`,
		time.Now())
	if err == nil {
		t.Fatal("STRICT accepted a time.Time in an _ms column")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "integer") {
		t.Fatalf("want a type error naming the INTEGER column, got: %v", err)
	}
}

// TestClosedVocabulariesMatchDDL — перечни domain.All*() и списки CHECK … IN
// в миграции обязаны совпадать. Это то самое механическое обеспечение, ради
// которого All*() существуют: разъезд между Go и схемой обнаруживается тестом,
// а не в проде на первом же неожиданном значении.
func TestClosedVocabulariesMatchDDL(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	cases := []struct {
		table  string
		column string
		want   []string
	}{
		{"users", "role", asStrings(domain.AllRoles())},
		{"users", "state", asStrings(domain.AllUserStates())},
		{"users", "kdf_algo", asStrings(domain.AllKDFAlgos())},
		{"resources", "namespace", asStrings(domain.AllNamespaces())},
		{"resources", "kind", asStrings(domain.AllKinds())},
		{"resources", "checksum_algo", asStrings(domain.AllChecksumAlgos())},
		{"uploads", "state", asStrings(domain.AllUploadStates())},
		{"uploads", "overwrite_mode", asStrings(domain.AllOverwriteModes())},
		{"uploads", "expected_checksum_algo", asStrings(domain.AllChecksumAlgos())},
		{"versions", "checksum_algo", asStrings(domain.AllChecksumAlgos())},
		{"trash_entries", "namespace", asStrings(domain.AllNamespaces())},
		{"trash_entries", "kind", asStrings(domain.AllKinds())},
		{"changes", "namespace", asStrings(domain.AllNamespaces())},
		{"changes", "kind", asStrings(domain.AllKinds())},
		{"changes", "operation", asStrings(domain.AllChangeOps())},
		{"changes", "checksum_algo", asStrings(domain.AllChecksumAlgos())},
		{"shares", "state", asStrings(domain.AllShareStates())},
		{"audit_events", "result", asStrings(domain.AllAuditResults())},
		{"blob_gc", "reason", asStrings(domain.AllGCReasons())},
		{"server_secrets", "name", asStrings(domain.AllSecretNames())},
	}
	for _, c := range cases {
		t.Run(c.table+"."+c.column, func(t *testing.T) {
			ddl := objectDDL(t, ctx, d, c.table)
			got := checkList(t, ddl, c.column)
			if !equalSets(got, c.want) {
				t.Fatalf("CHECK (%s IN …) = %v, domain declares %v", c.column, got, c.want)
			}
		})
	}
}

// TestActiveUploadStatesMatchPartialIndexes — предикаты частичных уникальных
// индексов §6.4 обязаны перечислять ровно нетерминальные состояния. Ошибка
// здесь не ловится ни одним функциональным тестом: индекс просто перестанет
// защищать от гонки, оставшись синтаксически корректным.
func TestActiveUploadStatesMatchPartialIndexes(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	want := asStrings(domain.ActiveUploadStates())
	for _, index := range []string{"uploads_client_key", "uploads_active_target"} {
		t.Run(index, func(t *testing.T) {
			ddl := objectDDL(t, ctx, d, index)
			got := checkList(t, ddl, "state")
			if !equalSets(got, want) {
				t.Fatalf("%s predicate = %v, domain.ActiveUploadStates() = %v", index, got, want)
			}
		})
	}
}

// TestSeedSystemAccount — §6.2: запись id = 0 создаётся в любой инсталляции.
func TestSeedSystemAccount(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	var (
		id                       int64
		login, role, state, algo string
		salt, storedKey          []byte
		authIters                int
		kdfParams                sql.NullString
		quota, used, reserved    int64
		pendingDelete            sql.NullInt64
		createdAtMs, updatedAtMs int64
	)
	err := d.Reader.QueryRowContext(ctx, `
SELECT id, login, role, state, kdf_algo, salt, stored_key, auth_iters, kdf_params,
       quota_bytes, used_bytes, reserved_bytes, pending_delete_at_ms,
       created_at_ms, updated_at_ms
FROM users WHERE id = 0`).Scan(&id, &login, &role, &state, &algo, &salt, &storedKey,
		&authIters, &kdfParams, &quota, &used, &reserved, &pendingDelete,
		&createdAtMs, &updatedAtMs)
	if err != nil {
		t.Fatalf("system account: %v", err)
	}
	if login != domain.SystemLogin {
		t.Errorf("login = %q, want %q", login, domain.SystemLogin)
	}
	if role != string(domain.RoleAdmin) {
		t.Errorf("role = %q, want %q", role, domain.RoleAdmin)
	}
	if state != string(domain.UserDisabled) {
		t.Errorf("state = %q, want %q", state, domain.UserDisabled)
	}
	if algo != string(domain.KDFPBKDF2SHA256) {
		t.Errorf("kdf_algo = %q, want %q", algo, domain.KDFPBKDF2SHA256)
	}
	// §6.2 п. 2: соль детерминирована и одинакова по правилу до M14.
	if got, want := string(salt), string(domain.LegacySalt(domain.SystemLogin)); got != want {
		t.Errorf("salt = %q, want %q", got, want)
	}
	if len(storedKey) != 32 {
		t.Errorf("len(stored_key) = %d, want 32", len(storedKey))
	}
	// §6.2 п. 3: значение обязано совпадать с остальными записями, иначе старт
	// отвергается как ошибка конфигурации.
	if authIters != testAuthIters {
		t.Errorf("auth_iters = %d, want %d", authIters, testAuthIters)
	}
	if kdfParams.Valid {
		t.Errorf("kdf_params = %q, want NULL for pbkdf2-sha256", kdfParams.String)
	}
	if quota != 0 || used != 0 || reserved != 0 {
		t.Errorf("quota/used/reserved = %d/%d/%d, want zeros", quota, used, reserved)
	}
	if pendingDelete.Valid {
		t.Error("pending_delete_at_ms must be NULL while state is not pending_delete")
	}
	if createdAtMs <= 0 || updatedAtMs <= 0 {
		t.Errorf("timestamps = %d/%d, want epoch milliseconds", createdAtMs, updatedAtMs)
	}

	// AUTOINCREMENT обязан выдать следующему пользователю id = 1, а не 0.
	now := int64(domain.NowMillis())
	res, err := d.Writer.ExecContext(ctx, `
INSERT INTO users (login, role, state, kdf_algo, salt, stored_key, auth_iters,
                   quota_bytes, used_bytes, reserved_bytes, created_at_ms, updated_at_ms)
VALUES ('alice', 'user', 'active', 'pbkdf2-sha256', ?, ?, ?, 0, 0, 0, ?, ?)`,
		domain.LegacySalt("alice"), make([]byte, 32), testAuthIters, now, now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if got, _ := res.LastInsertId(); got != 1 {
		t.Fatalf("first non-system user id = %d, want 1", got)
	}
}

// TestSeedPublicRoot — §6.3: корень /public создаётся миграцией и принадлежит
// системному аккаунту; id = parent_id, name пусто, kind = dir.
func TestSeedPublicRoot(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	var id, parentID, name, kind string
	var owner int64
	err := d.Reader.QueryRowContext(ctx, `
SELECT id, parent_id, owner_user_id, name, kind
FROM resources WHERE namespace = 'public' AND deleted_at_ms IS NULL`).
		Scan(&id, &parentID, &owner, &name, &kind)
	if err != nil {
		t.Fatalf("public root: %v", err)
	}
	if id != parentID {
		t.Errorf("id %q != parent_id %q: the root must be detached from the tree", id, parentID)
	}
	if owner != int64(domain.SystemUserID) {
		t.Errorf("owner_user_id = %d, want %d", owner, domain.SystemUserID)
	}
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
	if kind != string(domain.KindDir) {
		t.Errorf("kind = %q, want %q", kind, domain.KindDir)
	}
	if _, err := domain.ParseResourceID(id); err != nil {
		t.Errorf("root id is not canonical: %v", err)
	}
}

// TestSeedServerSecrets — §6.12: обе строки создаются миграцией, по 32 байта.
func TestSeedServerSecrets(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	values := map[string][]byte{}
	rows, err := d.Reader.QueryContext(ctx,
		`SELECT name, value, rotated_at_ms FROM server_secrets`)
	if err != nil {
		t.Fatalf("server_secrets: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name    string
			value   []byte
			rotated sql.NullInt64
		)
		if err := rows.Scan(&name, &value, &rotated); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(value) != domain.SecretValueLen {
			t.Errorf("secret %s: len = %d, want %d", name, len(value), domain.SecretValueLen)
		}
		if rotated.Valid {
			t.Errorf("secret %s: rotated_at_ms must be NULL on a fresh database", name)
		}
		values[name] = value
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("server_secrets: %v", err)
	}
	for _, name := range domain.AllSecretNames() {
		if _, ok := values[string(name)]; !ok {
			t.Errorf("secret %s is missing", name)
		}
	}
	if len(values) == 2 &&
		string(values[string(domain.SecretPageTokenKey)]) == string(values[string(domain.SecretServerSecret)]) {
		t.Fatal("both secrets got the same value")
	}
}

// TestMigrationIsIdempotent — §6.4 п. 9 ADR 0001. Повторный запуск не меняет
// базу; отдельно проверено, что секреты и корень /public НЕ пересоздаются:
// регенерация page_token_key обесценила бы все выданные токены.
func TestMigrationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	snapshot := func(d *db.DB) (rootID string, secrets map[string]string) {
		secrets = map[string]string{}
		if err := d.Reader.QueryRowContext(ctx,
			`SELECT id FROM resources WHERE namespace = 'public'`).Scan(&rootID); err != nil {
			t.Fatalf("public root: %v", err)
		}
		rows, err := d.Reader.QueryContext(ctx, `SELECT name, hex(value) FROM server_secrets`)
		if err != nil {
			t.Fatalf("secrets: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				t.Fatalf("scan: %v", err)
			}
			secrets[name] = value
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("secrets: %v", err)
		}
		return rootID, secrets
	}

	first := open(t, dir)
	rootBefore, secretsBefore := snapshot(first)
	var appliedAt int64
	if err := first.Reader.QueryRowContext(ctx,
		`SELECT applied_at_ms FROM schema_migrations WHERE version = 1`).Scan(&appliedAt); err != nil {
		t.Fatalf("applied_at_ms: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := open(t, dir)
	rootAfter, secretsAfter := snapshot(second)

	if rootAfter != rootBefore {
		t.Errorf("public root id changed on reopen: %s -> %s", rootBefore, rootAfter)
	}
	for name, before := range secretsBefore {
		if secretsAfter[name] != before {
			t.Errorf("secret %s was regenerated on reopen", name)
		}
	}
	var appliedAfter int64
	if err := second.Reader.QueryRowContext(ctx,
		`SELECT applied_at_ms FROM schema_migrations WHERE version = 1`).Scan(&appliedAfter); err != nil {
		t.Fatalf("applied_at_ms: %v", err)
	}
	if appliedAfter != appliedAt {
		t.Errorf("schema_migrations rewritten on reopen: %d -> %d", appliedAt, appliedAfter)
	}
	var count int
	if err := second.Reader.QueryRowContext(ctx,
		`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("users: %v", err)
	}
	if count != 1 {
		t.Errorf("users count = %d after reopen, want 1", count)
	}
}

// TestUniqueNameIsPartial — §6.3, §10.1: живое имя уникально, удалённое место
// не занимает, две удалённые строки с одним именем сосуществуют.
func TestUniqueNameIsPartial(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	root := publicRoot(t, ctx, d)

	first := insertFile(t, ctx, d, root, "report.pdf")
	if _, err := insertFileErr(ctx, d, root, "report.pdf"); err == nil {
		t.Fatal("duplicate live name accepted")
	}

	softDelete(t, ctx, d, first)
	second := insertFile(t, ctx, d, root, "report.pdf")

	softDelete(t, ctx, d, second)
	if _, err := insertFileErr(ctx, d, root, "report.pdf"); err != nil {
		t.Fatalf("insert after both were trashed: %v", err)
	}

	var trashed int
	if err := d.Reader.QueryRowContext(ctx, `
SELECT count(*) FROM resources WHERE name = 'report.pdf' AND deleted_at_ms IS NOT NULL`).
		Scan(&trashed); err != nil {
		t.Fatalf("count: %v", err)
	}
	if trashed != 2 {
		t.Fatalf("trashed rows with the same name = %d, want 2", trashed)
	}
}

// TestForeignKeysEnforced — §6.1: FK включены на соединении, нарушение
// отклоняется, а не проходит молча.
func TestForeignKeysEnforced(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	root := publicRoot(t, ctx, d)

	id, err := domain.NewResourceID()
	if err != nil {
		t.Fatal(err)
	}
	now := int64(domain.NowMillis())
	_, err = d.Writer.ExecContext(ctx, `
INSERT INTO resources (id, owner_user_id, parent_id, namespace, name, name_fold, kind,
                       created_at_ms, updated_at_ms)
VALUES (?, 4242, ?, 'public', 'orphan.bin', 'orphan.bin', 'file', ?, ?)`,
		id.String(), root, now, now)
	if err == nil {
		t.Fatal("resource with a non-existent owner accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("want a foreign key error, got: %v", err)
	}
}

// TestSystemAccountCannotBeDeletedWhileOwning — RESTRICT на users(id) означает,
// что строку пользователя нельзя удалить, пока существует хоть один его ресурс
// (§6.11). Каскад не удалил бы ни одного файла с диска, поэтому purge обязан
// выполнять работу явно и по шагам (§7.4).
func TestSystemAccountCannotBeDeletedWhileOwning(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	_, err := d.Writer.ExecContext(ctx, `DELETE FROM users WHERE id = 0`)
	if err == nil {
		t.Fatal("system account deleted while it still owns the public root")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("want a foreign key error, got: %v", err)
	}
}

// ─── вспомогательное ─────────────────────────────────────────────────────────

func publicRoot(t *testing.T, ctx context.Context, d *db.DB) string {
	t.Helper()
	var id string
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT id FROM resources WHERE namespace = 'public' AND id = parent_id`).Scan(&id); err != nil {
		t.Fatalf("public root: %v", err)
	}
	return id
}

func insertFileErr(ctx context.Context, d *db.DB, parent, name string) (string, error) {
	id, err := domain.NewResourceID()
	if err != nil {
		return "", err
	}
	now := int64(domain.NowMillis())
	_, err = d.Writer.ExecContext(ctx, `
INSERT INTO resources (id, owner_user_id, parent_id, namespace, name, name_fold, kind,
                       size_bytes, created_at_ms, updated_at_ms)
VALUES (?, 0, ?, 'public', ?, ?, 'file', 0, ?, ?)`,
		id.String(), parent, name, strings.ToLower(name), now, now)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func insertFile(t *testing.T, ctx context.Context, d *db.DB, parent, name string) string {
	t.Helper()
	id, err := insertFileErr(ctx, d, parent, name)
	if err != nil {
		t.Fatalf("insert %q: %v", name, err)
	}
	return id
}

// softDelete переводит строку в удалённое состояние по §10.1: удалённый корень
// поддерева ссылается сам на себя, а CHECK связывает deleted_at_ms и
// trashed_root_id в обе стороны.
func softDelete(t *testing.T, ctx context.Context, d *db.DB, id string) {
	t.Helper()
	_, err := d.Writer.ExecContext(ctx,
		`UPDATE resources SET deleted_at_ms = ?, trashed_root_id = id WHERE id = ?`,
		int64(domain.NowMillis()), id)
	if err != nil {
		t.Fatalf("soft delete %s: %v", id, err)
	}
}

func objectDDL(t *testing.T, ctx context.Context, d *db.DB, name string) string {
	t.Helper()
	var ddl string
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE name = ?`, name).Scan(&ddl); err != nil {
		t.Fatalf("ddl of %s: %v", name, err)
	}
	return ddl
}

var quoted = regexp.MustCompile(`'([^']*)'`)

// checkList вытаскивает список значений из «… column IN ('a','b') …» в DDL —
// он одинаков и для табличного CHECK, и для предиката частичного индекса.
func checkList(t *testing.T, ddl, column string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(column) + `\s+IN\s*\(([^)]*)\)`)
	m := re.FindStringSubmatch(ddl)
	if m == nil {
		t.Fatalf("no `%s IN (…)` found in:\n%s", column, ddl)
	}
	var out []string
	for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
		out = append(out, q[1])
	}
	if len(out) == 0 {
		t.Fatalf("empty value list for %s in:\n%s", column, ddl)
	}
	return out
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}

// asStrings приводит любой строковый словарь domain к []string.
func asStrings[T ~string](vals []T) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = string(v)
	}
	return out
}
