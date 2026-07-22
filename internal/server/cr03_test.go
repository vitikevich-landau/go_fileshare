package server_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
)

// TestActiveDownloadSurvivesIdleTimeout covers CR-03: a transfer that runs
// longer than idle_timeout_s must not be reaped as idle. A 256 KB/s limit on a
// ~768 KB file makes the download span several 1 s idle windows.
func TestActiveDownloadSurvivesIdleTimeout(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) {
		s.Limits.IdleTimeoutS = 1
		s.Limits.PerClientBps = 256 * 1024
	})
	const size = 768 * 1024
	want := makeFile(t, filepath.Join(e.share, "slow.bin"), size)

	c := dialNoAuth(t, e)
	dst := filepath.Join(t.TempDir(), "slow.out")
	if err := c.Download("/slow.bin", dst, nil); err != nil {
		t.Fatalf("download reaped by idle timeout: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("download mismatch: got %d bytes, want %d", len(got), len(want))
	}
}
