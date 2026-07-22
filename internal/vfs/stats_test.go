package vfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ShareStats counts regular files and sums their sizes, refreshed in the
// background so callers never block on the walk.
func TestShareStats(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "hello") // 5
	writeFile(t, filepath.Join(root, "b.txt"), "hi")    // 2
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "c.txt"), "abc") // 3

	v, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// First call kicks off the async walk and returns zeros.
	if files, bytes := v.ShareStats(); files != 0 || bytes != 0 {
		t.Fatalf("first ShareStats = (%d,%d), want (0,0) before the walk completes", files, bytes)
	}

	deadline := time.After(3 * time.Second)
	var files, bytes uint64
	for {
		files, bytes = v.ShareStats()
		if files == 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("stats not computed in time: files=%d bytes=%d", files, bytes)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if bytes != 10 {
		t.Fatalf("total bytes = %d, want 10", bytes)
	}
}

// walkStats must count only regular files, excluding symlinks from both the
// count and the size (R6-9).
func TestShareStatsIgnoresSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real.txt"), "hello") // 5 bytes, regular

	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	files, bytes := walkStats(root)
	if files != 1 {
		t.Fatalf("files = %d, want 1 (the symlink must not be counted)", files)
	}
	if bytes != 5 {
		t.Fatalf("bytes = %d, want 5 (only the regular file)", bytes)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
