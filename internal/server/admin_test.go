package server_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func adminView(t *testing.T, c *client.Client) map[string]config.KeyInfo {
	t.Helper()
	raw, err := c.AdminGetConfig()
	if err != nil {
		t.Fatalf("AdminGetConfig: %v", err)
	}
	var rows []config.KeyInfo
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("parse admin config: %v", err)
	}
	m := map[string]config.KeyInfo{}
	for _, r := range rows {
		m[r.Key] = r
	}
	return m
}

func TestAdminGetAndSetConfig(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e) // no-auth => admin

	view := adminView(t, c)
	if view["limits.per_client_bps"].Value != "0" || !view["limits.per_client_bps"].Hot {
		t.Fatalf("unexpected per_client_bps row: %+v", view["limits.per_client_bps"])
	}
	if view["server.port"].Hot {
		t.Fatal("server.port must be marked restart, not hot")
	}

	ok, msg, err := c.AdminSet("limits.global_bps", "5000000")
	if err != nil || !ok {
		t.Fatalf("AdminSet hot key: ok=%v msg=%q err=%v", ok, msg, err)
	}
	if e.hub.Current().Limits.GlobalBps != 5_000_000 {
		t.Fatalf("global_bps not applied: %d", e.hub.Current().Limits.GlobalBps)
	}
	if adminView(t, c)["limits.global_bps"].Value != "5000000" {
		t.Fatal("admin view did not reflect the change")
	}

	// Restart key is rejected.
	if ok, _, _ := c.AdminSet("server.port", "6000"); ok {
		t.Fatal("AdminSet accepted a restart key")
	}
	// Invalid value is rejected.
	if ok, _, _ := c.AdminSet("limits.per_client_bps", "notanumber"); ok {
		t.Fatal("AdminSet accepted a non-numeric value")
	}
}

func TestAdminAccessDeniedForUser(t *testing.T) {
	e := newEnv(t, nil)
	e.users.SetUser("vit", proto.RoleUser, "pw", testIters)

	c, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.AdminStats(); err == nil {
		t.Fatal("user was allowed ADMIN_STATS")
	} else {
		var re *client.RemoteError
		if !errors.As(err, &re) || re.Code != proto.ErrAccessDenied {
			t.Fatalf("expected ACCESS_DENIED, got %v", err)
		}
	}
	if _, err := c.AdminGetConfig(); err == nil {
		t.Fatal("user was allowed ADMIN_GET_CONFIG")
	}
}

func TestAdminListAndKick(t *testing.T) {
	e := newEnv(t, nil)
	c1 := dialNoAuth(t, e)
	c2 := dialNoAuth(t, e)

	clients, err := c1.AdminListClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) < 2 {
		t.Fatalf("expected >=2 clients, got %d", len(clients))
	}

	// Kicking self is refused.
	if ok, _, _ := c1.AdminKick(c1.SessionID()); ok {
		t.Fatal("kicking self should be refused")
	}
	// Kick the other session.
	ok, _, err := c1.AdminKick(c2.SessionID())
	if err != nil || !ok {
		t.Fatalf("kick other: ok=%v err=%v", ok, err)
	}
	// c2's next request should fail (connection closed).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, err := c2.ListDir("/"); err != nil {
			break // kicked as expected
		}
		if time.Now().After(deadline) {
			t.Fatal("kicked client is still usable")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAdminStats(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e)
	st, err := c.AdminStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Version == "" || st.ActiveConns < 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

func TestAdminSetPersistsAndBroadcasts(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	e := newEnvWithConfig(t, cfgPath, nil)

	// A second client subscribes to config events.
	ch := make(chan proto.Message, 8)
	watcher := dialWithEvents(t, e, ch)
	if err := watcher.Subscribe(proto.SubConfig); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	admin := dialNoAuth(t, e)
	if ok, msg, err := admin.AdminSet("server.motd", "hello world"); err != nil || !ok {
		t.Fatalf("AdminSet: ok=%v msg=%q err=%v", ok, msg, err)
	}

	// Persisted to disk.
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not persisted: %v", err)
	}
	if !strings.Contains(string(b), "hello world") {
		t.Fatalf("persisted config missing motd:\n%s", b)
	}

	// Broadcast EVENT_CONFIG to the subscriber.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		watcher.PollEvents(100 * time.Millisecond)
		select {
		case m := <-ch:
			if ec, ok := m.(proto.EventConfig); ok && ec.Key == "server.motd" && ec.NewValue == "hello world" {
				return
			}
		default:
		}
	}
	t.Fatal("did not receive EVENT_CONFIG")
}

// TestLiveRateLimitThrottlesActiveDownload is the flagship M11 test: lowering /
// raising the limit changes the speed of an ALREADY-ACTIVE transfer
// (docs/tz/08-roadmap.md M11 "done when").
func TestLiveRateLimitThrottlesActiveDownload(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.PerClientBps = 1 << 20 }) // 1 MiB/s
	const size = 2 << 20                                                         // 2 MiB
	makeFile(t, filepath.Join(e.share, "big3.bin"), size)

	// Baseline: throttled the whole way (~2s at 1 MiB/s).
	c1 := dialNoAuth(t, e)
	t0 := time.Now()
	if err := c1.Download("/big3.bin", filepath.Join(t.TempDir(), "a.bin"), nil); err != nil {
		t.Fatal(err)
	}
	throttled := time.Since(t0)
	if throttled < 1500*time.Millisecond {
		t.Fatalf("baseline was not throttled (%v); limiter inactive?", throttled)
	}

	// Raise the limit to unlimited partway through an active download.
	c2 := dialNoAuth(t, e)
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = e.hub.Set("limits.per_client_bps", "0")
	}()
	t1 := time.Now()
	if err := c2.Download("/big3.bin", filepath.Join(t.TempDir(), "b.bin"), nil); err != nil {
		t.Fatal(err)
	}
	raised := time.Since(t1)

	if raised >= throttled {
		t.Fatalf("live limit change had no effect: throttled=%v raised=%v", throttled, raised)
	}
	if raised > throttled-500*time.Millisecond {
		t.Fatalf("raising the limit mid-download did not speed it up enough: throttled=%v raised=%v", throttled, raised)
	}
}
