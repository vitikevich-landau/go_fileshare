package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDatabaseDefaults — умолчания обязаны совпадать с таблицей
// docs/tz/10-cloud-drive-spec.md §19.3 значение в значение.
func TestDatabaseDefaults(t *testing.T) {
	d := Default().Database
	if !d.Enabled {
		t.Error("database.enabled default = false, want true")
	}
	if d.Path != "metadata.db" {
		t.Errorf("database.path default = %q, want metadata.db", d.Path)
	}
	if d.BusyTimeoutMs != 5000 {
		t.Errorf("database.busy_timeout_ms default = %d, want 5000", d.BusyTimeoutMs)
	}
	if d.Synchronous != SynchronousNormal {
		t.Errorf("database.synchronous default = %q, want %s", d.Synchronous, SynchronousNormal)
	}
}

// TestDatabaseValidate — правило §19.4 п. 17. Отдельно проверено, что «OFF»
// именно отвергается: значение допускает потерю уже закоммиченных транзакций и
// делает недостижимыми инварианты §2.2.
func TestDatabaseValidate(t *testing.T) {
	bad := []struct {
		name string
		mut  func(*Settings)
	}{
		{"synchronous OFF", func(s *Settings) { s.Database.Synchronous = "OFF" }},
		{"synchronous в нижнем регистре", func(s *Settings) { s.Database.Synchronous = "normal" }},
		{"synchronous пуст", func(s *Settings) { s.Database.Synchronous = "" }},
		{"busy_timeout 0", func(s *Settings) { s.Database.BusyTimeoutMs = 0 }},
		{"busy_timeout отрицателен", func(s *Settings) { s.Database.BusyTimeoutMs = -1 }},
		{"пустой path при enabled", func(s *Settings) { s.Database.Path = "" }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			s := Default()
			c.mut(&s)
			if msg := s.Validate(); msg == "" {
				t.Fatal("Validate accepted an invalid database section")
			} else if !strings.HasPrefix(msg, "database.") {
				t.Fatalf("Validate = %q, want a message naming the database key", msg)
			}
		})
	}

	good := []struct {
		name string
		mut  func(*Settings)
	}{
		{"FULL допустим", func(s *Settings) { s.Database.Synchronous = SynchronousFull }},
		{"пустой path при disabled", func(s *Settings) { s.Database.Enabled = false; s.Database.Path = "" }},
	}
	for _, c := range good {
		t.Run(c.name, func(t *testing.T) {
			s := Default()
			c.mut(&s)
			if msg := s.Validate(); msg != "" {
				t.Fatalf("Validate rejected a valid snapshot: %s", msg)
			}
		})
	}
}

// TestDatabaseKeysAreRestartOnly — все четыре ключа restart-only: Set обязан
// отвергать их понятной ошибкой, а не молча принимать изменение, которое не
// дойдёт до уже открытых соединений пула (ADR 0001 §4.2).
func TestDatabaseKeysAreRestartOnly(t *testing.T) {
	keys := map[ConfigKey]ConfigValue{
		"database.enabled":         "false",
		"database.path":            "other.db",
		"database.busy_timeout_ms": "10000",
		"database.synchronous":     SynchronousFull,
	}
	for key, value := range keys {
		t.Run(key, func(t *testing.T) {
			h := NewHub(Default())
			err := h.Set(key, value)
			if err == nil {
				t.Fatalf("Set(%q) accepted a restart-only key", key)
			}
			if !strings.Contains(err.Error(), "restart") {
				t.Fatalf("Set(%q) = %v, want a message about restart", key, err)
			}
			if h.Current().Database != Default().Database {
				t.Fatalf("Set(%q) mutated the snapshot", key)
			}
		})
	}
}

// TestDatabaseInAdminView — ключи видны в админ-панели и помечены restart-only
// (§19.3, столбец «когда применяется»).
func TestDatabaseInAdminView(t *testing.T) {
	want := map[ConfigKey]ConfigValue{
		"database.enabled":         "true",
		"database.path":            "metadata.db",
		"database.busy_timeout_ms": "5000",
		"database.synchronous":     SynchronousNormal,
	}
	seen := map[ConfigKey]bool{}
	for _, ki := range Default().AdminView() {
		w, ok := want[ki.Key]
		if !ok {
			continue
		}
		seen[ki.Key] = true
		if ki.Value != w {
			t.Errorf("AdminView[%q] = %q, want %q", ki.Key, ki.Value, w)
		}
		if ki.Hot {
			t.Errorf("AdminView[%q] marked hot, want restart-only", ki.Key)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("AdminView is missing %q", key)
		}
	}
}

// TestDatabaseOverlay — частичный конфиг переопределяет только заданные ключи
// секции, остальные остаются умолчаниями §19.3.
func TestDatabaseOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"database":{"path":"/var/lib/fshare/metadata.db"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Database.Path != "/var/lib/fshare/metadata.db" {
		t.Errorf("database.path = %q", s.Database.Path)
	}
	if s.Database.BusyTimeoutMs != 5000 || s.Database.Synchronous != SynchronousNormal || !s.Database.Enabled {
		t.Errorf("partial overlay clobbered database defaults: %+v", s.Database)
	}
}

// TestDatabaseRejectedOnLoad — негодная секция отвергается при загрузке файла, а
// не при первом обращении к базе.
func TestDatabaseRejectedOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"database":{"synchronous":"OFF"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted database.synchronous = OFF")
	}
}
