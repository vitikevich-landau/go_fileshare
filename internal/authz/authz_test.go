package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/authz"
	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/storage"
)

const testAuthIters = 4096

type env struct {
	svc    *authz.Service
	db     *db.DB
	users  *metadata.Users
	res    *metadata.Resources
	layout storage.Layout
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	d, err := db.Open(ctx, db.Config{
		Path:          filepath.Join(dir, "metadata.db"),
		BusyTimeoutMs: 5000,
		Synchronous:   "NORMAL",
		ReadConns:     4,
	}, metadata.Migrations(metadata.SeedParams{AuthIters: testAuthIters}))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	layout, err := storage.New(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	if err := layout.EnsureSkeleton(); err != nil {
		t.Fatalf("EnsureSkeleton: %v", err)
	}

	res := metadata.NewResources(d)
	users := metadata.NewUsers(d, res)
	svc, err := authz.New(authz.Config{Users: users, Resources: res, Layout: layout})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	return &env{svc: svc, db: d, users: users, res: res, layout: layout}
}

func (e *env) user(t *testing.T, login string, role domain.Role) metadata.User {
	t.Helper()
	ctx := context.Background()
	var out metadata.User
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		u, err := e.users.Create(ctx, tx, metadata.NewUser{
			Login: login, Role: role,
			Secret: metadata.Secret{
				KDFAlgo:   domain.KDFPBKDF2SHA256,
				Salt:      domain.LegacySalt(login),
				StoredKey: make([]byte, 32),
				AuthIters: testAuthIters,
			},
		})
		out = u
		return err
	})
	if err != nil {
		t.Fatalf("Create(%q): %v", login, err)
	}
	return out
}

// mkdir создаёт каталог в дереве и возвращает его.
func (e *env) mkdir(t *testing.T, owner domain.UserID, ns domain.Namespace, parent domain.ResourceID, name string) metadata.Resource {
	t.Helper()
	ctx := context.Background()
	var out metadata.Resource
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := e.res.Create(ctx, tx, metadata.NewResource{
			OwnerUserID: owner, ParentID: parent, Namespace: ns, Name: name, Kind: domain.KindDir,
		}, true)
		out = r
		return err
	})
	if err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	return out
}

func (e *env) context(t *testing.T, u metadata.User) authz.UserContext {
	t.Helper()
	uc, err := e.svc.Context(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("Context(%q): %v", u.Login, err)
	}
	t.Cleanup(func() { uc.Close() })
	return uc
}

// TestContextOpensLockedHomeRoot — §7.2: per-user os.Root открывается ДО первой
// файловой операции сессии, и границу удерживает он сам, а не проверки в
// обработчиках.
func TestContextOpensLockedHomeRoot(t *testing.T) {
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	bob := e.user(t, "bob", domain.RoleUser)

	uc := e.context(t, alice)
	if uc.UserID != alice.ID || uc.Login != "alice" || uc.Role != domain.RoleUser {
		t.Errorf("UserContext = %+v", uc)
	}
	if uc.HomeRoot == nil {
		t.Fatal("HomeRoot не открыт")
	}
	if got, want := uc.HomeRoot.Name(), e.layout.UserLive(alice.ID); got != want {
		t.Errorf("HomeRoot = %q, want %q", got, want)
	}

	// Файл в home другого пользователя недостижим через корень первого — ни
	// относительным путём с «..», ни абсолютным.
	bobRoot, err := e.layout.OpenUserHome(bob.ID)
	if err != nil {
		t.Fatalf("OpenUserHome(bob): %v", err)
	}
	defer bobRoot.Close()
	if err := os.WriteFile(filepath.Join(e.layout.UserLive(bob.ID), "secret.txt"),
		[]byte("bob"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, escape := range []string{
		filepath.Join("..", "..", filepath.Base(e.layout.UserDir(bob.ID)), "live", "secret.txt"),
		"../../" + filepath.Base(e.layout.UserDir(bob.ID)) + "/live/secret.txt",
	} {
		if _, err := uc.HomeRoot.Open(escape); err == nil {
			t.Errorf("корень alice открыл %q из home bob", escape)
		}
	}
}

// TestContextRejectsSystemAccount — §6.2: у системного аккаунта нет /home.
func TestContextRejectsSystemAccount(t *testing.T) {
	e := newEnv(t)
	uc, err := e.svc.Context(context.Background(), domain.SystemUserID)
	if err == nil {
		uc.Close()
		t.Fatal("системному аккаунту собран UserContext")
	}
	if !errors.Is(err, authz.ErrAccessDenied) {
		t.Errorf("err = %v, ожидалась ErrAccessDenied", err)
	}
	if _, err := os.Stat(e.layout.UserDir(domain.SystemUserID)); !os.IsNotExist(err) {
		t.Errorf("каталог системного аккаунта создан: %v", err)
	}
}

// TestContextRejectsInactiveUser — §7.4: disabled не получает новой сессии. Между
// аутентификацией и открытием корня пользователь может быть отключён
// административной командой, поэтому состояние проверяется и здесь.
func TestContextRejectsInactiveUser(t *testing.T) {
	ctx := context.Background()
	for _, state := range []domain.UserState{domain.UserDisabled, domain.UserPendingDelete} {
		t.Run(string(state), func(t *testing.T) {
			e := newEnv(t)
			u := e.user(t, "alice", domain.RoleUser)
			err := e.db.Write(ctx, func(tx *sql.Tx) error {
				return e.users.SetState(ctx, tx, u.ID, state)
			})
			if err != nil {
				t.Fatalf("SetState: %v", err)
			}
			if uc, err := e.svc.Context(ctx, u.ID); !errors.Is(err, authz.ErrAccessDenied) {
				uc.Close()
				t.Fatalf("Context вернул %v, ожидалась ErrAccessDenied", err)
			}
		})
	}
}

// TestContextRejectsMissingUser — идентификатор без строки users даёт ErrNotFound,
// а не пустой контекст.
func TestContextRejectsMissingUser(t *testing.T) {
	e := newEnv(t)
	if uc, err := e.svc.Context(context.Background(), 4242); !errors.Is(err, authz.ErrNotFound) {
		uc.Close()
		t.Fatalf("Context вернул %v, ожидалась ErrNotFound", err)
	}
}

// TestRefreshRereadsRoleAndKeepsRoot — «пересчёт UserContext» §7.4 п. 3: сессия
// сохраняется, роль перечитывается, корень остаётся тем же дескриптором.
func TestRefreshRereadsRoleAndKeepsRoot(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u := e.user(t, "alice", domain.RoleUser)
	uc := e.context(t, u)

	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		return e.users.SetRole(ctx, tx, u.ID, domain.RoleAdmin)
	})
	if err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// До пересчёта прежнее значение остаётся в копии сессии — именно поэтому §7.4
	// требует пересчёта, а не полагается на то, что кто-то перечитает роль сам.
	if uc.IsAdmin() {
		t.Fatal("роль изменилась в старой копии контекста")
	}

	fresh, err := e.svc.Refresh(ctx, uc)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !fresh.IsAdmin() {
		t.Errorf("Refresh не перечитал роль: %+v", fresh)
	}
	if fresh.HomeRoot != uc.HomeRoot {
		t.Error("Refresh переоткрыл корень: дескриптор сессии обязан остаться тем же")
	}
	if _, err := fresh.HomeRoot.Stat("."); err != nil {
		t.Errorf("корень после Refresh нерабочий: %v", err)
	}
}

// TestRefreshFailsForRevokedUser — если к моменту пересчёта пользователь удалён
// или отключён, сессию обязан закрыть вызывающий, а не продолжить работу со
// старой ролью.
func TestRefreshFailsForRevokedUser(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	u := e.user(t, "alice", domain.RoleUser)
	uc := e.context(t, u)

	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		return e.users.SetState(ctx, tx, u.ID, domain.UserDisabled)
	})
	if err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if _, err := e.svc.Refresh(ctx, uc); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("Refresh вернул %v, ожидалась ErrAccessDenied", err)
	}
}

// TestResolveHomeIsOwnHome — DoD M12: пользователь A не видит home пользователя B
// прямым путём. Изоляция обеспечена конструкцией — /home разрешается в home
// ВЫЗЫВАЮЩЕГО, и одинаковый путь у двух сессий даёт разные ресурсы.
func TestResolveHomeIsOwnHome(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	bob := e.user(t, "bob", domain.RoleUser)

	aliceHome, err := e.res.HomeRoot(ctx, alice.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	bobHome, err := e.res.HomeRoot(ctx, bob.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	e.mkdir(t, alice.ID, domain.NamespaceHome, aliceHome.ID, "docs")
	e.mkdir(t, bob.ID, domain.NamespaceHome, bobHome.ID, "docs")

	aliceCtx := e.context(t, alice)
	bobCtx := e.context(t, bob)

	aliceDocs, err := e.svc.Resolve(ctx, aliceCtx, "", "/home/docs")
	if err != nil {
		t.Fatalf("Resolve(alice): %v", err)
	}
	bobDocs, err := e.svc.Resolve(ctx, bobCtx, "", "/home/docs")
	if err != nil {
		t.Fatalf("Resolve(bob): %v", err)
	}
	if aliceDocs.ID == bobDocs.ID {
		t.Fatal("один путь разрешился в один ресурс для двух пользователей")
	}
	if aliceDocs.OwnerUserID != alice.ID || bobDocs.OwnerUserID != bob.ID {
		t.Errorf("владельцы разошлись: %d и %d", aliceDocs.OwnerUserID, bobDocs.OwnerUserID)
	}
}

// TestResolveRootAndNested — корень namespace и вложенный путь.
func TestResolveRootAndNested(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	home, err := e.res.HomeRoot(ctx, alice.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	docs := e.mkdir(t, alice.ID, domain.NamespaceHome, home.ID, "docs")
	deep := e.mkdir(t, alice.ID, domain.NamespaceHome, docs.ID, "2026")
	uc := e.context(t, alice)

	publicRoot, err := e.res.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}

	tests := map[string]domain.ResourceID{
		"/home":           home.ID,
		"/home/docs":      docs.ID,
		"/home/docs/2026": deep.ID,
		"/public":         publicRoot.ID,
	}
	for path, want := range tests {
		got, err := e.svc.Resolve(ctx, uc, "", path)
		if err != nil {
			t.Errorf("Resolve(%q): %v", path, err)
			continue
		}
		if got.ID != want {
			t.Errorf("Resolve(%q) = %s, want %s", path, got.ID, want)
		}
	}
}

// TestResolveRejects — таблица отказов: форма пути (§5.3) отличается от «нет
// такого ресурса», потому что коды разные (INVALID_NAME против NOT_FOUND).
func TestResolveRejects(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	home, err := e.res.HomeRoot(ctx, alice.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	e.mkdir(t, alice.ID, domain.NamespaceHome, home.ID, "docs")
	uc := e.context(t, alice)

	tests := []struct {
		name string
		ns   domain.Namespace
		path string
		want error
	}{
		{"не абсолютный", "", "home/docs", authz.ErrInvalidPath},
		{"неизвестный namespace", "", "/files/docs", authz.ErrInvalidPath},
		{"v2-путь без namespace", "", "/docs", authz.ErrInvalidPath},
		{"компонент «..»", "", "/home/../public", authz.ErrInvalidPath},
		{"namespace противоречит пути", domain.NamespacePublic, "/home/docs", authz.ErrInvalidPath},
		{"нет такого компонента", "", "/home/missing", authz.ErrNotFound},
		{"путь сквозь несуществующий каталог", "", "/home/missing/deeper", authz.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := e.svc.Resolve(ctx, uc, tt.ns, tt.path); !errors.Is(err, tt.want) {
				t.Fatalf("Resolve(%q) вернул %v, ожидалась %v", tt.path, err, tt.want)
			}
		})
	}
}

// TestResolveMatchingNamespaceIsAccepted — непустой namespace, совпадающий с
// путём, не мешает: §27 объявляет его аргументом, и вызывающий вправе его
// передать.
func TestResolveMatchingNamespaceIsAccepted(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	uc := e.context(t, alice)

	if _, err := e.svc.Resolve(ctx, uc, domain.NamespaceHome, "/home"); err != nil {
		t.Errorf("Resolve с совпадающим namespace: %v", err)
	}
	if _, err := e.svc.Resolve(ctx, uc, domain.NamespacePublic, "/public"); err != nil {
		t.Errorf("Resolve с совпадающим namespace public: %v", err)
	}
}

// TestVisible — правила §7.3 этого этапа: home виден только владельцу (включая
// администратора — DoD M12 оговорок по роли не делает), public виден всем.
func TestVisible(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	bob := e.user(t, "bob", domain.RoleUser)
	root := e.user(t, "root", domain.RoleAdmin)

	aliceHome, err := e.res.HomeRoot(ctx, alice.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	aliceDocs := e.mkdir(t, alice.ID, domain.NamespaceHome, aliceHome.ID, "docs")

	publicRoot, err := e.res.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	shared := e.mkdir(t, alice.ID, domain.NamespacePublic, publicRoot.ID, "shared")

	aliceCtx := e.context(t, alice)
	bobCtx := e.context(t, bob)
	rootCtx := e.context(t, root)

	tests := []struct {
		name string
		uc   authz.UserContext
		res  domain.ResourceID
		want bool
	}{
		{"свой home", aliceCtx, aliceDocs.ID, true},
		{"чужой home", bobCtx, aliceDocs.ID, false},
		{"чужой home для администратора", rootCtx, aliceDocs.ID, false},
		{"свой корень home", aliceCtx, aliceHome.ID, true},
		{"чужой корень home", bobCtx, aliceHome.ID, false},
		{"public владельцу", aliceCtx, shared.ID, true},
		{"public другому пользователю", bobCtx, shared.ID, true},
		{"public администратору", rootCtx, shared.ID, true},
		{"корень public", bobCtx, publicRoot.ID, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.svc.Visible(ctx, tt.uc, tt.res)
			if err != nil {
				t.Fatalf("Visible: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Visible = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVisibleHidesTrashedPublicFromOthers — содержимое корзины видно только
// владельцу: trash-запись лежит под его user-id (§7.3, §10), и остальным о ней
// знать нечего.
func TestVisibleHidesTrashedPublicFromOthers(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	bob := e.user(t, "bob", domain.RoleUser)

	publicRoot, err := e.res.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	shared := e.mkdir(t, alice.ID, domain.NamespacePublic, publicRoot.ID, "shared")

	// Удаление в корзину — операция M15; здесь достаточно того, что схема
	// выражает: deleted_at_ms и trashed_root_id заполнены вместе.
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE resources
SET deleted_at_ms = ?, trashed_root_id = ?, parent_id = id WHERE id = ?`,
			int64(domain.NowMillis()), shared.ID.String(), shared.ID.String())
		return err
	})
	if err != nil {
		t.Fatalf("перевод в корзину: %v", err)
	}

	aliceCtx := e.context(t, alice)
	bobCtx := e.context(t, bob)

	if visible, err := e.svc.Visible(ctx, aliceCtx, shared.ID); err != nil || !visible {
		t.Errorf("владелец не видит свой ресурс в корзине: %v, %v", visible, err)
	}
	if visible, err := e.svc.Visible(ctx, bobCtx, shared.ID); err != nil || visible {
		t.Errorf("чужой ресурс в корзине виден: %v, %v", visible, err)
	}
}

// TestVisibleMissingResourceIsAnError — событие о неизвестном ресурсе — дефект, а
// не отказ в доступе, и вызывающий обязан различать эти случаи.
func TestVisibleMissingResourceIsAnError(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	alice := e.user(t, "alice", domain.RoleUser)
	uc := e.context(t, alice)

	id, err := domain.NewResourceID()
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	if _, err := e.svc.Visible(ctx, uc, id); !errors.Is(err, authz.ErrNotFound) {
		t.Fatalf("Visible вернул %v, ожидалась ErrNotFound", err)
	}
}

// TestNewRejectsIncompleteConfig — половинчато собранный сервис принимал бы
// решения о доступе без источника истины.
func TestNewRejectsIncompleteConfig(t *testing.T) {
	e := newEnv(t)
	tests := map[string]authz.Config{
		"без users":     {Resources: e.res, Layout: e.layout},
		"без resources": {Users: e.users, Layout: e.layout},
		"без раскладки": {Users: e.users, Resources: e.res},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := authz.New(cfg); err == nil {
				t.Fatal("New принял неполный Config")
			}
		})
	}
}
