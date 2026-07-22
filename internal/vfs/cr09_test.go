package vfs

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChecksumInvalidatesOnSubSecondChange covers CR-09: a same-size change
// within the same wall-clock second must not return a stale cached checksum.
// The two versions are given mtimes in the same second but different
// sub-second parts; a second-granularity key would collide.
func TestChecksumInvalidatesOnSubSecondChange(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "f.bin")

	if err := os.WriteFile(p, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	tA := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(p, tA, tA); err != nil {
		t.Fatal(err)
	}

	v, err := New(root, filepath.Join(t.TempDir(), "c.cache"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	if _, _, _, err := v.Checksum("/f.bin"); err != nil { // primes the cache
		t.Fatal(err)
	}

	// Same size, different content, same second but a different sub-second mtime.
	if err := os.WriteFile(p, []byte("BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	tB := time.Unix(1_700_000_000, 500_000_000)
	if err := os.Chtimes(p, tB, tB); err != nil {
		t.Fatal(err)
	}

	_, _, got, err := v.Checksum("/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("BBBB"))
	if got != want {
		t.Fatalf("stale checksum returned: got %x, want %x", got, want)
	}
}

// TestChecksumInvalidatesOnPreservedMtimeChange covers RR-5: content replaced
// with the mtime restored to its exact previous value still invalidates the
// cache, via change-time. Skips where change-time is unavailable (e.g. Windows).
func TestChecksumInvalidatesOnPreservedMtimeChange(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "f.bin")
	if err := os.WriteFile(p, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); changeTimeNanos(info) == 0 {
		t.Skip("change-time unavailable on this platform")
	}

	fixed := time.Unix(1_700_000_000, 424242)
	if err := os.Chtimes(p, fixed, fixed); err != nil {
		t.Fatal(err)
	}

	v, err := New(root, filepath.Join(t.TempDir(), "c.cache"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, _, _, err := v.Checksum("/f.bin"); err != nil { // prime
		t.Fatal(err)
	}

	// Replace content (same size) and restore the exact previous mtime.
	if err := os.WriteFile(p, []byte("BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, fixed, fixed); err != nil {
		t.Fatal(err)
	}

	_, _, got, err := v.Checksum("/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("BBBB"))
	if got != want {
		t.Fatalf("stale checksum despite content change with preserved mtime: got %x, want %x", got, want)
	}
}
