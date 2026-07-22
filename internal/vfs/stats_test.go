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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
