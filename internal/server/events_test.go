package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func dialWithEvents(t *testing.T, e *env, ch chan proto.Message) *client.Client {
	t.Helper()
	c, err := client.Dial(e.addr, client.Options{
		Login: "tester",
		EventHandler: func(m proto.Message) {
			select {
			case ch <- m:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestLiveEventOnCreate covers the full path: fsnotify watcher -> debounce ->
// EVENT_FS broadcast -> subscribed client (docs/tz/08-roadmap.md M10 "done when").
func TestLiveEventOnCreate(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Events.DebounceMs = 40 })
	ch := make(chan proto.Message, 32)
	c := dialWithEvents(t, e, ch)

	if err := c.Subscribe(proto.SubFS); err != nil {
		t.Fatal(err)
	}
	// Give the subscription a beat to register, then drop a file into the share.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(e.share, "arrived.bin"), []byte("hello new"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.PollEvents(150 * time.Millisecond); err != nil {
			t.Fatalf("poll: %v", err)
		}
		select {
		case m := <-ch:
			ev, ok := m.(proto.EventFs)
			if ok && strings.HasSuffix(ev.Path, "arrived.bin") {
				if ev.Op != proto.FsCreated {
					t.Fatalf("op = %v, want CREATED", ev.Op)
				}
				return // success
			}
		default:
		}
	}
	t.Fatal("did not receive EVENT_FS for the created file within 3s")
}

// TestEventNotBroadcastWithoutSubscribe ensures unsubscribed clients are not
// pushed filesystem events.
func TestEventNotBroadcastWithoutSubscribe(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Events.DebounceMs = 40 })
	ch := make(chan proto.Message, 32)
	c := dialWithEvents(t, e, ch)
	// No Subscribe call.

	time.Sleep(50 * time.Millisecond)
	os.WriteFile(filepath.Join(e.share, "silent.bin"), []byte("x"), 0o644)

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		c.PollEvents(100 * time.Millisecond)
		select {
		case m := <-ch:
			if ev, ok := m.(proto.EventFs); ok && strings.HasSuffix(ev.Path, "silent.bin") {
				t.Fatal("received EVENT_FS without subscribing")
			}
		default:
		}
	}
}
