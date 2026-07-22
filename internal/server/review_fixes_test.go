package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestListWithOverlongNameDoesNotBreak covers the fix for a filename longer than
// the wire's 255-byte name cap (legal on NTFS for multi-byte unicode): it must
// be hidden rather than poisoning the whole ListDirResponse. Skips where the OS
// won't create such a name (e.g. Linux NAME_MAX = 255 bytes).
func TestListWithOverlongNameDoesNotBreak(t *testing.T) {
	e := newEnv(t, nil)
	longName := strings.Repeat("あ", 100) // 300 UTF-8 bytes
	if err := os.WriteFile(filepath.Join(e.share, longName), []byte("x"), 0o644); err != nil {
		t.Skipf("cannot create a >255-byte-name file on this OS: %v", err)
	}

	c := dialNoAuth(t, e)
	_, entries, err := c.ListDir("/")
	if err != nil {
		t.Fatalf("listing broke because of an over-long name: %v", err)
	}
	for _, en := range entries {
		if en.Name == longName {
			t.Fatal("an over-long name should be hidden from the listing")
		}
	}
}
