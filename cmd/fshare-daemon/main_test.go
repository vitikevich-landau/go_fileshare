package main

import (
	"log/slog"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
)

// TestApplyReload covers RR-4: a SIGHUP reload preserves restart-only keys
// (including events.*), applies hot keys, and updates the live log LevelVar.
func TestApplyReload(t *testing.T) {
	base := config.Default()
	base.Server.Port = 5555
	base.Server.ShareRoot = "/orig/share"
	base.Events.DebounceMs = 500
	base.Log.Level = "info"
	hub := config.NewHub(base)

	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)

	next := config.Default()
	next.Server.Port = 9999         // restart -> must be ignored
	next.Server.ShareRoot = "/evil" // restart -> ignored
	next.Events.DebounceMs = 999    // restart (events) -> ignored
	next.Log.Level = "debug"        // hot -> applied to snapshot AND LevelVar
	next.Server.Motd = "reloaded"   // hot -> applied

	if err := applyReload(hub, lv, next); err != nil {
		t.Fatal(err)
	}

	cur := hub.Current()
	if cur.Server.Port != 5555 || cur.Server.ShareRoot != "/orig/share" {
		t.Fatalf("restart server keys not preserved: %+v", cur.Server)
	}
	if cur.Events.DebounceMs != 500 {
		t.Fatalf("events.* not preserved: %d", cur.Events.DebounceMs)
	}
	if cur.Log.Level != "debug" || cur.Server.Motd != "reloaded" {
		t.Fatalf("hot keys not applied: level=%s motd=%q", cur.Log.Level, cur.Server.Motd)
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatalf("log LevelVar not updated on reload: %v", lv.Level())
	}
}
