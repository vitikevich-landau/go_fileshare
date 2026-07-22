package server_test

import (
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func dialAs(t *testing.T, e *env, login, pw string, ch chan proto.Message) *client.Client {
	t.Helper()
	c, err := client.Dial(e.addr, client.Options{
		Login: login, Password: pw,
		EventHandler: func(m proto.Message) {
			select {
			case ch <- m:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("dial %s: %v", login, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// gotConfigEvent polls c for up to d and reports whether an EVENT_CONFIG for key
// arrives.
func gotConfigEvent(c *client.Client, ch chan proto.Message, key string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c.PollEvents(100 * time.Millisecond)
		select {
		case m := <-ch:
			if ec, ok := m.(proto.EventConfig); ok && ec.Key == key {
				return true
			}
		default:
		}
	}
	return false
}

// TestUserCannotSubscribeToConfigEvents covers CR-07: a non-admin's SubConfig
// bit is dropped, so it never receives EVENT_CONFIG, while an admin does.
func TestUserCannotSubscribeToConfigEvents(t *testing.T) {
	e := newEnv(t, nil)
	e.users.SetUser("vit", proto.RoleUser, "pw", testIters)
	e.users.SetUser("root", proto.RoleAdmin, "apw", testIters)

	uch := make(chan proto.Message, 16)
	user := dialAs(t, e, "vit", "pw", uch)
	if err := user.Subscribe(proto.SubConfig | proto.SubFS); err != nil {
		t.Fatal(err)
	}
	ach := make(chan proto.Message, 16)
	admin := dialAs(t, e, "root", "apw", ach)
	if err := admin.Subscribe(proto.SubConfig); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// A config change fires EVENT_CONFIG to SubConfig subscribers.
	if err := e.hub.Set("server.motd", "hello"); err != nil {
		t.Fatal(err)
	}

	if !gotConfigEvent(admin, ach, "server.motd", 2*time.Second) {
		t.Fatal("admin subscriber did not receive EVENT_CONFIG")
	}
	if gotConfigEvent(user, uch, "server.motd", 1*time.Second) {
		t.Fatal("non-admin received EVENT_CONFIG despite role filtering")
	}
}
