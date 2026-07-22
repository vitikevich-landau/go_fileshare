package tui

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/server"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// dialLoopbackClient starts a no-auth daemon on an ephemeral port and returns a
// real connected client, so tests can exercise doDisconnect with a genuine
// non-nil *client.Client (an empty users DB means any login authenticates).
func dialLoopbackClient(t *testing.T) *client.Client {
	t.Helper()
	share := t.TempDir()
	cfg := config.Default()
	cfg.Server.ShareRoot = share
	hub := config.NewHub(cfg)

	v, err := vfs.New(share, filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	users, err := auth.Load(filepath.Join(t.TempDir(), "users.json")) // absent => no-auth
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Options{
		Hub: hub, VFS: v, Users: users, Guard: auth.NewGuard(3), ServerName: "t",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, time.Second); close(done) }()
	t.Cleanup(func() { cancel(); <-done; v.Close() })

	c, err := client.Dial(srv.Addr().String(), client.Options{Login: "tester"})
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	return c
}

// The m.client pointer write in doDisconnect must be synchronized with the
// locked background readers (pump/commands). With a REAL non-nil client, the
// pre-fix code took the unsynchronized-write path and this test fails under
// -race; the fixed code clears the pointer under clientMu. Run with -race.
func TestDisconnectClientPointerNoRace(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m.screen = screenCommander
	m.panels = [2]*Panel{newPanel(false, "l", "/"), newPanel(true, "r", "/")}
	m.client = dialLoopbackClient(t) // genuine non-nil client

	// A background reader touches m.client under the lock, exactly like the pump.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				m.clientMu.Lock()
				_ = m.client
				m.clientMu.Unlock()
			}
		}
	}()

	m.doDisconnect() // closes the real socket, then clears m.client under the lock
	close(stop)
	<-done

	if m.client != nil {
		t.Fatal("disconnect should clear the client pointer")
	}
}
