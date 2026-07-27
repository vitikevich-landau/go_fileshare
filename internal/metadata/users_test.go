package metadata_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// repos — обе репозитория поверх одной свежей базы.
func repos(t *testing.T) (*db.DB, *metadata.Users, *metadata.Resources) {
	t.Helper()
	d := open(t, t.TempDir())
	res := metadata.NewResources(d)
	return d, metadata.NewUsers(d, res), res
}

// secretFor собирает KDF-материал по правилам §6.2 п. 2: до раунда AUTH_PARAMS
// (M14) соль детерминирована и равна "fileshare-v2:" || login у ВСЕХ записей.
func secretFor(login string) metadata.Secret {
	return metadata.Secret{
		KDFAlgo:   domain.KDFPBKDF2SHA256,
		Salt:      domain.LegacySalt(login),
		StoredKey: make([]byte, 32),
		AuthIters: testAuthIters,
	}
}

func createUser(t *testing.T, d *db.DB, us *metadata.Users, in metadata.NewUser) (metadata.User, error) {
	t.Helper()
	var (
		out metadata.User
		err error
	)
	txErr := d.Write(context.Background(), func(tx *sql.Tx) error {
		out, err = us.Create(context.Background(), tx, in)
		return err
	})
	if err == nil && txErr != nil {
		t.Fatalf("commit: %v", txErr)
	}
	return out, err
}

func newUser(login string, role domain.Role) metadata.NewUser {
	return metadata.NewUser{Login: login, Role: role, Secret: secretFor(login)}
}

// TestCreateUserSideEffects — создание пользователя обязано затронуть ТРИ
// таблицы: users, корень /home в resources (§6.3) и строку journal_state его
// потока (§6.7). Последняя проверяется отдельно и придирчиво: её отсутствие не
// проявляется никакой ошибкой во время работы — compaction §14.6 шаг 3 просто
// молча обновит ноль строк, и журнал потока перестанет ужиматься.
func TestCreateUserSideEffects(t *testing.T) {
	ctx := context.Background()
	d, us, res := repos(t)

	u, err := createUser(t, d, us, metadata.NewUser{
		Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice"), QuotaBytes: 20 << 30,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// AUTOINCREMENT выдаёт новым пользователям id начиная с 1, поэтому с
	// системным аккаунтом id = 0 коллизии не возникает (§6.2).
	if u.ID == domain.SystemUserID {
		t.Fatalf("новый пользователь получил id системного аккаунта (%d)", u.ID)
	}
	if u.State != domain.UserActive {
		t.Errorf("state = %q, ожидалось active по умолчанию", u.State)
	}

	got, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if got.ID != u.ID || got.Role != domain.RoleUser || got.QuotaBytes != 20<<30 {
		t.Errorf("ByLogin вернул %+v, не совпадает с созданным", got)
	}
	if string(got.Secret.Salt) != string(domain.LegacySalt("alice")) {
		t.Errorf("salt = %q, want %q (§6.2 п. 2)", got.Secret.Salt, domain.LegacySalt("alice"))
	}
	if got.Secret.KDFParams != "" {
		t.Errorf("kdf_params = %q, при pbkdf2-sha256 ожидался NULL (§6.2 п. 4)", got.Secret.KDFParams)
	}
	if got.PendingDeleteAt != 0 {
		t.Errorf("pending_delete_at_ms = %d у активного пользователя", got.PendingDeleteAt)
	}

	home, err := res.HomeRoot(ctx, u.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	if !home.IsRoot() || home.Kind != domain.KindDir || home.Name != "" {
		t.Errorf("корень /home имеет неверную форму: %+v", home)
	}
	if home.OwnerUserID != u.ID {
		t.Errorf("корень /home принадлежит %d, want %d (§6.3)", home.OwnerUserID, u.ID)
	}

	var baselineID string
	err = d.Reader.QueryRowContext(ctx,
		`SELECT baseline_id FROM journal_state WHERE user_id = ?`, int64(u.ID)).Scan(&baselineID)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("у нового пользователя нет строки journal_state (§6.7, §14.6): " +
			"её отсутствие не даёт ошибки, журнал просто перестаёт ужиматься")
	}
	if err != nil {
		t.Fatalf("читать journal_state: %v", err)
	}
	if baselineID == "" {
		t.Error("journal_state.baseline_id пуст (§14.6)")
	}
}

// TestCreateUserLoginTaken — логин занят, в том числе у пользователя в
// pending_delete: §6.2 требует не освобождать его до purge, иначе новый
// пользователь унаследует audit-историю старого.
func TestCreateUserLoginTaken(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	u, err := createUser(t, d, us, newUser("bob", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := createUser(t, d, us, newUser("bob", domain.RoleAdmin)); !errors.Is(err, metadata.ErrLoginExists) {
		t.Errorf("повторный логин = %v, want ErrLoginExists", err)
	}

	if err := d.Write(ctx, func(tx *sql.Tx) error {
		return us.SetState(ctx, tx, u.ID, domain.UserPendingDelete)
	}); err != nil {
		t.Fatalf("SetState(pending_delete): %v", err)
	}
	if _, err := createUser(t, d, us, newUser("bob", domain.RoleUser)); !errors.Is(err, metadata.ErrLoginExists) {
		t.Errorf("логин удаляемого пользователя = %v, want ErrLoginExists (§6.2)", err)
	}

	// Логин системного аккаунта занят миграцией.
	if _, err := createUser(t, d, us, newUser(domain.SystemLogin, domain.RoleAdmin)); !errors.Is(err, metadata.ErrLoginExists) {
		t.Errorf("логин %q = %v, want ErrLoginExists", domain.SystemLogin, err)
	}
}

// TestSetStatePendingDeleteColumn — схема требует, чтобы pending_delete_at_ms
// был заполнен РОВНО тогда, когда состояние равно pending_delete. Проверяется
// оба перехода: туда и обратно.
func TestSetStatePendingDeleteColumn(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	u, err := createUser(t, d, us, newUser("carol", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	set := func(state domain.UserState) metadata.User {
		t.Helper()
		if err := d.Write(ctx, func(tx *sql.Tx) error {
			return us.SetState(ctx, tx, u.ID, state)
		}); err != nil {
			t.Fatalf("SetState(%s): %v", state, err)
		}
		got, err := us.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		return got
	}

	got := set(domain.UserPendingDelete)
	if got.State != domain.UserPendingDelete || got.PendingDeleteAt == 0 {
		t.Errorf("после pending_delete: state = %q, pending_delete_at_ms = %d; ожидались pending_delete и ненулевой момент",
			got.State, got.PendingDeleteAt)
	}
	got = set(domain.UserDisabled)
	if got.State != domain.UserDisabled || got.PendingDeleteAt != 0 {
		t.Errorf("после возврата в disabled: state = %q, pending_delete_at_ms = %d; ожидались disabled и NULL",
			got.State, got.PendingDeleteAt)
	}
}

// TestSetters — каждый мутатор меняет своё поле, двигает updated_at_ms и
// отвечает ErrNotFound на несуществующего пользователя. Последнее существенно:
// без проверки числа затронутых строк смена роли несуществующей учётки
// завершилась бы успехом.
func TestSetters(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	u, err := createUser(t, d, us, newUser("dave", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	write := func(fn func(*sql.Tx) error) error { return d.Write(ctx, fn) }

	if err := write(func(tx *sql.Tx) error { return us.SetRole(ctx, tx, u.ID, domain.RoleAdmin) }); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := write(func(tx *sql.Tx) error { return us.SetQuota(ctx, tx, u.ID, 0) }); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	newSecret := metadata.Secret{
		KDFAlgo:   domain.KDFPBKDF2SHA256,
		Salt:      domain.LegacySalt("dave"),
		StoredKey: []byte(strings.Repeat("k", 32)),
		AuthIters: testAuthIters,
	}
	if err := write(func(tx *sql.Tx) error { return us.SetSecret(ctx, tx, u.ID, newSecret) }); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	got, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Role != domain.RoleAdmin {
		t.Errorf("role = %q, want admin", got.Role)
	}
	if got.QuotaBytes != 0 {
		t.Errorf("quota_bytes = %d, want 0 (unlimited)", got.QuotaBytes)
	}
	if string(got.Secret.StoredKey) != strings.Repeat("k", 32) {
		t.Error("stored_key не обновился")
	}
	if got.UpdatedAt < got.CreatedAt {
		t.Errorf("updated_at_ms = %d меньше created_at_ms = %d", got.UpdatedAt, got.CreatedAt)
	}

	const missing = domain.UserID(9999)
	notFound := []struct {
		name string
		call func(*sql.Tx) error
	}{
		{"SetRole", func(tx *sql.Tx) error { return us.SetRole(ctx, tx, missing, domain.RoleUser) }},
		{"SetQuota", func(tx *sql.Tx) error { return us.SetQuota(ctx, tx, missing, 1) }},
		{"SetState", func(tx *sql.Tx) error { return us.SetState(ctx, tx, missing, domain.UserDisabled) }},
		{"SetSecret", func(tx *sql.Tx) error { return us.SetSecret(ctx, tx, missing, newSecret) }},
	}
	for _, tc := range notFound {
		if err := write(tc.call); !errors.Is(err, metadata.ErrNotFound) {
			t.Errorf("%s(несуществующий) = %v, want ErrNotFound", tc.name, err)
		}
	}
}

// TestCountActiveAdmins — множество, которое инвариант 13 (§2.2, §7.4) запрещает
// опустошать. Системный аккаунт в него не входит: он admin, но disabled.
func TestCountActiveAdmins(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	count := func() int {
		t.Helper()
		var n int
		if err := d.Write(ctx, func(tx *sql.Tx) error {
			var err error
			n, err = us.CountActiveAdmins(ctx, tx)
			return err
		}); err != nil {
			t.Fatalf("CountActiveAdmins: %v", err)
		}
		return n
	}

	if got := count(); got != 0 {
		t.Errorf("на свежей базе активных админов %d, want 0: системный аккаунт disabled (§6.2)", got)
	}
	admin, err := createUser(t, d, us, newUser("root", domain.RoleAdmin))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := count(); got != 1 {
		t.Errorf("после создания админа %d, want 1", got)
	}
	if _, err := createUser(t, d, us, newUser("user1", domain.RoleUser)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := count(); got != 1 {
		t.Errorf("обычный пользователь попал в счёт админов: %d", got)
	}
	// disable последнего админа опустошает множество — это и есть ситуация, ради
	// которой считаем.
	if err := d.Write(ctx, func(tx *sql.Tx) error {
		return us.SetState(ctx, tx, admin.ID, domain.UserDisabled)
	}); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if got := count(); got != 0 {
		t.Errorf("после disable админа %d, want 0", got)
	}
}

// TestCreateUserRejects — предусловия, которые схема выразить не может.
func TestCreateUserRejects(t *testing.T) {
	d, us, _ := repos(t)

	cases := []struct {
		why  string
		in   metadata.NewUser
		want error
	}{
		{"пустой логин", metadata.NewUser{Role: domain.RoleUser, Secret: secretFor("")}, metadata.ErrInvalidLogin},
		{
			"логин с переводом строки",
			metadata.NewUser{Login: "a\nb", Role: domain.RoleUser, Secret: secretFor("a\nb")},
			metadata.ErrInvalidLogin,
		},
		{
			"логин длиннее предела",
			metadata.NewUser{
				Login:  strings.Repeat("x", metadata.MaxLoginLen+1),
				Role:   domain.RoleUser,
				Secret: secretFor("x"),
			},
			metadata.ErrInvalidLogin,
		},
		{"роль вне словаря", metadata.NewUser{Login: "u", Role: "root", Secret: secretFor("u")}, nil},
		{
			"создание сразу в pending_delete",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, State: domain.UserPendingDelete, Secret: secretFor("u")},
			nil,
		},
		{"отрицательная квота", metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: secretFor("u"), QuotaBytes: -1}, nil},
		{
			"пустая соль",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: metadata.Secret{
				KDFAlgo: domain.KDFPBKDF2SHA256, StoredKey: make([]byte, 32), AuthIters: testAuthIters,
			}},
			nil,
		},
		{
			"pbkdf2 с нулевыми итерациями",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: metadata.Secret{
				KDFAlgo: domain.KDFPBKDF2SHA256, Salt: domain.LegacySalt("u"), StoredKey: make([]byte, 32),
			}},
			nil,
		},
		{
			"pbkdf2 с заполненным kdf_params",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: metadata.Secret{
				KDFAlgo: domain.KDFPBKDF2SHA256, Salt: domain.LegacySalt("u"), StoredKey: make([]byte, 32),
				AuthIters: testAuthIters, KDFParams: "m=65536,t=3,p=1",
			}},
			nil,
		},
		{
			"argon2id с ненулевыми итерациями",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: metadata.Secret{
				KDFAlgo: domain.KDFArgon2id, Salt: domain.LegacySalt("u"), StoredKey: make([]byte, 32),
				AuthIters: testAuthIters, KDFParams: "m=65536,t=3,p=1",
			}},
			nil,
		},
		{
			"argon2id без kdf_params",
			metadata.NewUser{Login: "u", Role: domain.RoleUser, Secret: metadata.Secret{
				KDFAlgo: domain.KDFArgon2id, Salt: domain.LegacySalt("u"), StoredKey: make([]byte, 32),
			}},
			nil,
		},
	}
	for _, tc := range cases {
		_, err := createUser(t, d, us, tc.in)
		if err == nil {
			t.Errorf("%s: Create вернул nil, ожидалась ошибка", tc.why)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: Create = %v, ожидалась обёртка %v", tc.why, err, tc.want)
		}
	}
}

// TestCreateUserRollback — при откате транзакции не остаётся ни строки users, ни
// корня /home, ни строки journal_state. Проверяется явно, потому что Create
// пишет в три таблицы: частичный результат дал бы пользователя без домашнего
// каталога либо корень без владельца.
func TestCreateUserRollback(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	sentinel := errors.New("откат по требованию теста")
	var created metadata.User
	err := d.Write(ctx, func(tx *sql.Tx) error {
		var err error
		created, err = us.Create(ctx, tx, newUser("erin", domain.RoleUser))
		if err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write = %v, ожидался откат", err)
	}

	if _, err := us.ByLogin(ctx, "erin"); !errors.Is(err, metadata.ErrNotFound) {
		t.Errorf("после отката ByLogin = %v, want ErrNotFound", err)
	}
	var homes, journals int
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT count(*) FROM resources WHERE namespace = ?`, string(domain.NamespaceHome)).Scan(&homes); err != nil {
		t.Fatalf("считать корни /home: %v", err)
	}
	if homes != 0 {
		t.Errorf("после отката осталось %d корней /home", homes)
	}
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT count(*) FROM journal_state WHERE user_id = ?`, int64(created.ID)).Scan(&journals); err != nil {
		t.Fatalf("считать journal_state: %v", err)
	}
	if journals != 0 {
		t.Errorf("после отката осталось %d строк journal_state", journals)
	}
}

// TestListIncludesSystemAccount — List отдаёт таблицу как есть, включая
// системный аккаунт: решение, показывать ли его в `user list` (§7.4), принимает
// слой команды, а не хранилище.
func TestListIncludesSystemAccount(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	if _, err := createUser(t, d, us, newUser("frank", domain.RoleUser)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	list, err := us.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List вернул %d записей, want 2 (system + frank)", len(list))
	}
	if !list[0].IsSystem() || list[0].Login != domain.SystemLogin {
		t.Errorf("первой записью ожидался системный аккаунт, получено %+v", list[0])
	}
	if list[0].State != domain.UserDisabled {
		t.Errorf("системный аккаунт в состоянии %q, want disabled (§6.2)", list[0].State)
	}
	if list[1].Login != "frank" || list[1].IsSystem() {
		t.Errorf("второй записью ожидался frank, получено %+v", list[1])
	}
}
