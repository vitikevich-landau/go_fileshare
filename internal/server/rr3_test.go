package server_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
)

// TestDownloadCancelKeepsConnInSync covers RR-3: cancelling a download aborts it
// with context.Canceled, and the server's terminal frame leaves the connection
// in sync so it is immediately reusable.
func TestDownloadCancelKeepsConnInSync(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.PerClientBps = 128 * 1024 }) // slow
	makeFile(t, filepath.Join(e.share, "big.slow"), 1<<20)                          // ~8s at 128 KB/s

	c := dialNoAuth(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond) // let a few chunks flow, then cancel
		cancel()
	}()

	err := c.DownloadCtx(ctx, "/big.slow", filepath.Join(t.TempDir(), "out.bin"), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled download returned %v, want context.Canceled", err)
	}

	// The connection must remain usable (in sync) right after a cancel.
	if _, _, lerr := c.ListDir("/"); lerr != nil {
		t.Fatalf("connection desynced after cancel: %v", lerr)
	}
}
