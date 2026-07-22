package server

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// TestHotLogLevelTakesEffect covers CR-08: ADMIN_SET/log.level changes the live
// logger's threshold, not just the stored snapshot.
func TestHotLogLevelTakesEffect(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: lv}))

	share := t.TempDir()
	v, err := vfs.New(share, filepath.Join(t.TempDir(), "c.cache"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close() // release the os.Root handle before TempDir cleanup (Windows)
	users, _ := auth.Load(filepath.Join(t.TempDir(), "users.json"))
	hub := config.NewHub(config.Default())
	New(Options{Hub: hub, VFS: v, Users: users, Guard: auth.NewGuard(3), Logger: logger, LogLevel: lv})

	logger.Debug("before")
	if strings.Contains(buf.String(), "before") {
		t.Fatal("debug was emitted at default info level")
	}

	if err := hub.Set("log.level", "debug"); err != nil {
		t.Fatal(err)
	}
	logger.Debug("after-debug")
	if !strings.Contains(buf.String(), "after-debug") {
		t.Fatal("debug not emitted after setting log.level=debug")
	}

	if err := hub.Set("log.level", "info"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	logger.Debug("after-info")
	if strings.Contains(buf.String(), "after-info") {
		t.Fatal("debug still emitted after reverting log.level=info")
	}
}
