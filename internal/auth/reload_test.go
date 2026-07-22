package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// A missing users file on reload must be an error that keeps the previous set,
// never a silent drop to the no-auth (any login = ADMIN) bootstrap.
func TestReloadMissingFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := Load(path) // absent file → empty bootstrap DB
	if err != nil {
		t.Fatal(err)
	}
	db.SetUser("vit", proto.RoleUser, "pw", 4096)
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}

	// A normal reload from the present file works.
	if err := db.Reload(); err != nil {
		t.Fatalf("reload of present file: %v", err)
	}
	if db.Empty() {
		t.Fatal("db should contain vit after reload")
	}

	// Delete the file: reload must error and preserve the in-memory set.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := db.Reload(); err == nil {
		t.Fatal("reload of a missing file must return an error")
	}
	if db.Empty() {
		t.Fatal("db must keep the previous snapshot when reload fails (fail closed)")
	}
	if _, _, enabled, ok := db.Lookup("vit"); !ok || !enabled {
		t.Fatal("vit must still be present and enabled after a failed reload")
	}
}
