package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if msg := Default().Validate(); msg != "" {
		t.Fatalf("default settings invalid: %s", msg)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Server.Port != 5555 || s.Events.Enabled != true {
		t.Fatalf("missing file did not yield defaults: %+v", s)
	}
}

func TestLoadPartialOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"server":{"port":6000},"limits":{"per_client_bps":1000}}`), 0o644)
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Server.Port != 6000 {
		t.Errorf("port = %d, want 6000", s.Server.Port)
	}
	if s.Server.ShareRoot != "./share" {
		t.Errorf("share_root = %q, want default ./share", s.Server.ShareRoot)
	}
	if s.Limits.PerClientBps != 1000 {
		t.Errorf("per_client_bps = %d, want 1000", s.Limits.PerClientBps)
	}
	if !s.Events.Enabled {
		t.Error("events.enabled should stay true from defaults")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Settings)
	}{
		{"bad port", func(s *Settings) { s.Server.Port = 0 }},
		{"empty share_root", func(s *Settings) { s.Server.ShareRoot = "" }},
		{"per>global", func(s *Settings) { s.Limits.GlobalBps = 100; s.Limits.PerClientBps = 200 }},
		{"zero handshake", func(s *Settings) { s.Limits.HandshakeTimeoutS = 0 }},
		{"bad log level", func(s *Settings) { s.Log.Level = "verbose" }},
	}
	for _, c := range cases {
		s := Default()
		c.mut(&s)
		if s.Validate() == "" {
			t.Errorf("%s: expected validation error", c.name)
		}
	}
}

func TestSaveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s := Default()
	s.Server.Motd = "hi"
	s.Limits.GlobalBps = 5_000_000
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Motd != "hi" || got.Limits.GlobalBps != 5_000_000 {
		t.Fatalf("reloaded settings mismatch: %+v", got)
	}
}

func TestHubCurrentAndApply(t *testing.T) {
	h := NewHub(Default())
	if h.Current().Server.Port != 5555 {
		t.Fatal("hub seeded wrong")
	}
	next := Default()
	next.Server.Motd = "changed"
	if err := h.Apply(next); err != nil {
		t.Fatal(err)
	}
	if h.Current().Server.Motd != "changed" {
		t.Fatal("Apply did not swap snapshot")
	}
	// Apply rejects invalid settings.
	bad := Default()
	bad.Server.Port = 0
	if err := h.Apply(bad); err == nil {
		t.Fatal("Apply accepted invalid settings")
	}
}

func TestHubSetHotKey(t *testing.T) {
	h := NewHub(Default())
	var gotKey, gotVal string
	h.SetOnChange(func(k, v string) { gotKey, gotVal = k, v })

	if err := h.Set("limits.per_client_bps", "5000000"); err != nil {
		t.Fatal(err)
	}
	if h.Current().Limits.PerClientBps != 5_000_000 {
		t.Fatalf("per_client_bps = %d, want 5000000", h.Current().Limits.PerClientBps)
	}
	if gotKey != "limits.per_client_bps" || gotVal != "5000000" {
		t.Fatalf("onChange got (%q,%q)", gotKey, gotVal)
	}

	if err := h.Set("server.motd", "hello"); err != nil {
		t.Fatal(err)
	}
	if h.Current().Server.Motd != "hello" {
		t.Fatal("motd not applied")
	}
}

func TestHubSetRejectsRestartKey(t *testing.T) {
	h := NewHub(Default())
	if err := h.Set("server.port", "6000"); err == nil {
		t.Fatal("Set accepted a restart key")
	}
	if h.Current().Server.Port != 5555 {
		t.Fatal("restart key was applied despite rejection")
	}
}

func TestHubSetRejectsUnknownAndInvalid(t *testing.T) {
	h := NewHub(Default())
	if err := h.Set("limits.nonexistent", "1"); err == nil {
		t.Fatal("Set accepted unknown key")
	}
	if err := h.Set("limits.per_client_bps", "notanumber"); err == nil {
		t.Fatal("Set accepted non-numeric value")
	}
	if err := h.Set("limits.handshake_timeout_s", "-5"); err == nil {
		t.Fatal("Set accepted negative value")
	}
	// per_client > global must fail validation and leave snapshot unchanged.
	h.Set("limits.global_bps", "1000")
	if err := h.Set("limits.per_client_bps", "2000"); err == nil {
		t.Fatal("Set accepted per_client_bps > global_bps")
	}
	if h.Current().Limits.PerClientBps != 0 {
		t.Fatalf("rejected Set leaked into snapshot: per_client_bps=%d", h.Current().Limits.PerClientBps)
	}
}
