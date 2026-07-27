package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// Перенос как таковой проверен в internal/metadata; здесь проверяется обвязка
// команды: чтение файла, гейт database.enabled и то, что auth_iters приходит из
// действующего конфига, а не из умолчания.
func daemonConfig(t *testing.T) config.Settings {
	t.Helper()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "metadata.db")
	cfg.Auth.PBKDF2Iters = 700_000
	return cfg
}

func writeUsersFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("подготовка users.json: %v", err)
	}
	return path
}

const legacyUsers = `{"users":[
  {"login":"alice","role":"admin","stored_key":"` +
	`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","enabled":true}
]}`

func TestRunMigrateUsers(t *testing.T) {
	cfg := daemonConfig(t)
	path := writeUsersFile(t, legacyUsers)

	if err := runMigrateUsers(cfg, path, false); err != nil {
		t.Fatalf("runMigrateUsers: %v", err)
	}
	// Исходный файл не удаляется (§21.4).
	if _, err := os.Stat(path); err != nil {
		t.Errorf("исходный users.json пропал: %v", err)
	}

	meta, err := openMetadataDB(cfg)
	if err != nil {
		t.Fatalf("открыть базу после переноса: %v", err)
	}
	defer meta.Close()

	users := metadata.NewUsers(meta, metadata.NewResources(meta))
	alice, err := users.ByLogin(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if alice.Role != domain.RoleAdmin || alice.State != domain.UserActive {
		t.Errorf("role = %q, state = %q; ожидались admin и active", alice.Role, alice.State)
	}
	if alice.Secret.AuthIters != cfg.Auth.PBKDF2Iters {
		t.Errorf("auth_iters = %d, want %d из auth.pbkdf2_iters",
			alice.Secret.AuthIters, cfg.Auth.PBKDF2Iters)
	}

	// Повторный запуск идемпотентен и на уровне команды.
	if err := runMigrateUsers(cfg, path, false); err != nil {
		t.Fatalf("повторный запуск: %v", err)
	}
}

func TestRunMigrateUsersRequiresDatabase(t *testing.T) {
	cfg := daemonConfig(t)
	cfg.Database.Enabled = false
	err := runMigrateUsers(cfg, writeUsersFile(t, legacyUsers), false)
	if err == nil || !strings.Contains(err.Error(), "database.enabled") {
		t.Fatalf("runMigrateUsers при выключенной базе = %v, ожидалась ошибка про database.enabled", err)
	}
}

func TestRunMigrateUsersMissingFile(t *testing.T) {
	cfg := daemonConfig(t)
	missing := filepath.Join(t.TempDir(), "нет-такого.json")
	if err := runMigrateUsers(cfg, missing, false); err == nil {
		t.Fatal("отсутствующий файл принят")
	}
	// База не должна быть создана прежде, чем прочитан файл: иначе неудачная
	// команда оставляла бы за собой пустую metadata.db.
	if _, err := os.Stat(cfg.Database.Path); err == nil {
		t.Error("metadata.db создана несмотря на отсутствующий users.json")
	}
}

// TestRequestedModes — разовые режимы взаимоисключающи, и проверка обязана
// сработать ДО первой ветки: они идут цепочкой с return, поэтому пара вроде
// --migrate-only --migrate-users выполнила бы первую и молча пропустила вторую
// с нулевым кодом возврата.
func TestRequestedModes(t *testing.T) {
	cases := []struct {
		why  string
		got  []string
		want int
	}{
		{"ничего не задано", requestedModes(false, "", "", false, ""), 0},
		{"только --migrate-users", requestedModes(false, "", "", false, "users.json"), 1},
		{"только --check-config", requestedModes(true, "", "", false, ""), 1},
		{"--migrate-only и --migrate-users", requestedModes(false, "", "", true, "users.json"), 2},
		{"--check-config и --migrate-users", requestedModes(true, "", "", false, "users.json"), 2},
		{"--add-user и --reset-password", requestedModes(false, "vit", "vit", false, ""), 2},
		{"всё сразу", requestedModes(true, "a", "b", true, "users.json"), 5},
	}
	for _, tc := range cases {
		if len(tc.got) != tc.want {
			t.Errorf("%s: режимов %d (%v), want %d", tc.why, len(tc.got), tc.got, tc.want)
		}
	}
}

// TestMigrateUsersReportEscapesLogins — логины из чужого файла печатаются
// экранированными.
//
// validateLogin пропускает категорию Cf сознательно: ZWNJ законно встречается
// в именах. Но U+202E RIGHT-TO-LEFT OVERRIDE из той же категории, напечатанный
// как есть, переворачивает строку прямо в терминале оператора и прячет соседние
// записи отчёта. Решение принято такое: пускать в регистрацию, экранировать при
// выводе — значит, вывод обязан экранировать.
func TestMigrateUsersReportEscapesLogins(t *testing.T) {
	const rtlOverride = "\u202e"
	cfg := daemonConfig(t)
	body := `{"users":[{"login":"a` + rtlOverride + `b","role":"admin",` +
		`"stored_key":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",` +
		`"enabled":true}]}`
	path := writeUsersFile(t, body)

	out := captureStdout(t, func() {
		if err := runMigrateUsers(cfg, path, false); err != nil {
			t.Fatalf("runMigrateUsers: %v", err)
		}
	})
	if strings.Contains(out, rtlOverride) {
		t.Errorf("в отчёт попал U+202E как есть:\n%s", out)
	}
	if !strings.Contains(out, `\u202e`) {
		t.Errorf("логин не экранирован:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}
