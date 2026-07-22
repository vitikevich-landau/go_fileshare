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
// pre-fix code took the unsynchronized-write path; the fixed code clears the
// pointer under clientMu. Run with -race.
//
// Determinism: the reader performs a FIXED number of locked reads with no
// early-stop, and main enters doDisconnect only after the startup barrier. So
// every run executes both the write and all reads, and no happens-before edge
// orders the (buggy, unsynchronized) write against any read — close(done)/<-done
// only orders reader→main, never the reverse. The race detector compares vector
// clocks, not physical overlap, so it must flag the old code on EVERY run — even
// a scheduling where the write physically completes before the first read.
func TestDisconnectClientPointerNoRace(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m.screen = screenCommander
	m.panels = [2]*Panel{newPanel(false, "l", "/"), newPanel(true, "r", "/")}
	m.client = dialLoopbackClient(t) // genuine non-nil client

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started) // startup barrier: main proceeds only once we are live
		seen := 0
		for i := 0; i < 1000; i++ { // mandatory reads, never skipped
			m.clientMu.Lock()
			if m.client != nil { // a real use, so the load cannot be elided
				seen++
			}
			m.clientMu.Unlock()
		}
		_ = seen
	}()

	<-started
	m.doDisconnect() // closes the real socket, then clears m.client under the lock
	<-done           // every one of the 1000 reads has executed

	if m.client != nil {
		t.Fatal("disconnect should clear the client pointer")
	}
}
