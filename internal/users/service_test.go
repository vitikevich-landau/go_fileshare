package users_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
	"github.com/vitikevich-landau/go_fileshare/internal/storage"
	"github.com/vitikevich-landau/go_fileshare/internal/users"
)

// testAuthIters — действующее auth.pbkdf2_iters в тестах. Занижено: вывод ключа
// проверяется в internal/scram, здесь важно только то, что значение ОДНО.
const testAuthIters = 4096

// spy — реестры §7.4 под наблюдением. Записывает вызовы В ПОРЯДКЕ поступления,
// потому что таблица §7.4 требует не только «что сделано», но и «до того, как
// команда вернёт успех».
type spy struct {
	mu    sync.Mutex
	calls []string
}

func (s *spy) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *spy) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *spy) reset() {
	s.mu.Lock()
	s.calls = nil
	s.mu.Unlock()
}

func (s *spy) CloseUser(_ context.Context, _ domain.UserID) int {
	s.record("sessions.close")
	return 1
}

func (s *spy) Recompute(_ context.Context, _ domain.UserID) int {
	s.record("sessions.recompute")
	return 1
}

func (s *spy) RevokeUser(_ context.Context, _ domain.UserID) int {
	s.record("tokens.revoke")
	return 1
}

func (s *spy) SetUserShares(_ context.Context, _ domain.UserID, state users.ShareState) int {
	s.record("shares." + string(state))
	return 1
}

// env — сервис поверх свежей базы и пустого data root.
type env struct {
	svc    *users.Service
	spy    *spy
	db     *db.DB
	repo   *metadata.Users
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
	repo := metadata.NewUsers(d, res)
	sp := &spy{}

	svc, err := users.New(ctx, users.Config{
		DB:        d,
		Users:     repo,
		Resources: res,
		Layout:    layout,
		AuthIters: testAuthIters,
		Sessions:  sp,
		Tokens:    sp,
		Shares:    sp,
	})
	if err != nil {
		t.Fatalf("users.New: %v", err)
	}
	return &env{svc: svc, spy: sp, db: d, repo: repo, res: res, layout: layout}
}

// seed кладёт строку users НАПРЯМУЮ через репозиторий, минуя сервис.
//
// Так проверяется поведение сервиса на данных, которые он сам создать не мог бы:
// запись с argon2id (§6.2 п. 5), запись с чужим auth_iters, запись в состоянии,
// которое операция §7.4 назначает, а не выбирает. Для обычных случаев тесты
// пользуются svc.Create — он и есть проверяемый путь.
func (e *env) seed(t *testing.T, in metadata.NewUser) metadata.User {
	t.Helper()
	ctx := context.Background()
	var out metadata.User
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		u, err := e.repo.Create(ctx, tx, in)
		out = u
		return err
	})
	if err != nil {
		t.Fatalf("seed %q: %v", in.Login, err)
	}
	e.spy.reset()
	return out
}

// secretFor собирает KDF-материал по правилам §6.2 п. 1–4 для пароля: соль
// детерминирована (п. 2), auth_iters общий (п. 3), kdf_params пуст при
// pbkdf2-sha256 (п. 4).
func secretFor(login, password string) metadata.Secret {
	key := scram.StoredKey(password, domain.LegacySalt(login), testAuthIters)
	return metadata.Secret{
		KDFAlgo:   domain.KDFPBKDF2SHA256,
		Salt:      domain.LegacySalt(login),
		StoredKey: key[:],
		AuthIters: testAuthIters,
	}
}

// proofFor считает доказательство так, как его считает клиент: соль он выводит
// сам из логина (§6.2 п. 2), сервер её не присылает до M14.
func proofFor(login, password string, challenge []byte) scram.Proof {
	return scram.Prove(password, domain.LegacySalt(login), testAuthIters, challenge, login)
}

// TestNewRejectsIncompleteConfig — сервис, собранный наполовину, опаснее
// несобранного: он работает и молча не выполняет таблицу §7.4.
func TestNewRejectsIncompleteConfig(t *testing.T) {
	ctx := context.Background()
	full := newEnv(t)

	base := func() users.Config {
		return users.Config{
			DB:        full.db,
			Users:     full.repo,
			Resources: full.res,
			Layout:    full.layout,
			AuthIters: testAuthIters,
			Sessions:  full.spy,
		}
	}

	tests := map[string]func(*users.Config){
		"без DB":          func(c *users.Config) { c.DB = nil },
		"без репозитория": func(c *users.Config) { c.Users = nil },
		"без resources":   func(c *users.Config) { c.Resources = nil },
		"без раскладки":   func(c *users.Config) { c.Layout = storage.Layout{} },
		"без auth_iters":  func(c *users.Config) { c.AuthIters = 0 },
		"auth_iters < 0":  func(c *users.Config) { c.AuthIters = -1 },
		"без реестра":     func(c *users.Config) { c.Sessions = nil },
	}
	for name, broken := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			broken(&cfg)
			if _, err := users.New(ctx, cfg); err == nil {
				t.Fatal("New принял неполный Config")
			}
		})
	}

	// Локальные команды остановленного daemon (--init-admin, --promote,
	// --migrate-users) живых сессий не имеют по определению, и требовать от них
	// реестр значило бы заставить поднимать половину сервера (§7.5, §21.4).
	cfg := base()
	cfg.Sessions = nil
	cfg.AllowNoSessions = true
	if _, err := users.New(ctx, cfg); err != nil {
		t.Fatalf("New с AllowNoSessions: %v", err)
	}
}

// TestNewRejectsAuthItersDivergedFromConfig — §6.2 п. 3, §19.4 п. 19: повышение
// auth.pbkdf2_iters на непустой БД до M14 запрещено, и сборка сервиса обязана
// отказать.
//
// Проверять это иначе нечем. Расхождение не даёт ни одной наблюдаемой ошибки во
// время работы: клиент выводит ключ по значению из HELLO_OK, сервер сверяет его с
// верификатором, посчитанным по колонке, не сходится — и отвечает AUTH_FAIL, тем
// же ответом, что и на неверный пароль. Ни один пользователь не входит, и ни одна
// запись в логе не говорит почему.
func TestNewRejectsAuthItersDivergedFromConfig(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})

	cfg := users.Config{
		DB:        e.db,
		Users:     e.repo,
		Resources: e.res,
		Layout:    e.layout,
		AuthIters: testAuthIters * 2, // оператор поднял значение в конфиге
		Sessions:  e.spy,
	}
	if _, err := users.New(ctx, cfg); err == nil {
		t.Fatal("сервис собран на базе, чьи записи посчитаны с другим числом итераций")
	}

	// Прежнее значение — рабочее: правило запрещает расхождение, а не саму
	// величину.
	cfg.AuthIters = testAuthIters
	if _, err := users.New(ctx, cfg); err != nil {
		t.Fatalf("сборка с совпадающим значением: %v", err)
	}
}

// TestNewAllowsAnyItersOnFreshDatabase — свежая установка до --init-admin
// содержит только системный аккаунт, чьё значение проставила миграция и обновить
// нечем (§6.2). Требовать совпадения с ним значило бы запретить выбор
// auth.pbkdf2_iters на пустой базе — то есть при первой же установке.
func TestNewAllowsAnyItersOnFreshDatabase(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	_, err := users.New(ctx, users.Config{
		DB:        e.db,
		Users:     e.repo,
		Resources: e.res,
		Layout:    e.layout,
		AuthIters: testAuthIters * 3,
		Sessions:  e.spy,
	})
	if err != nil {
		t.Fatalf("сборка на пустой базе: %v", err)
	}
}
