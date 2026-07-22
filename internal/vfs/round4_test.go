package vfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestChecksumCtxCancels covers R4-3: a cache-miss checksum aborts promptly when
// its context is cancelled (so a cancelled transfer stops re-reading a large
// file), and a fresh context still computes the correct digest.
func TestChecksumCtxCancels(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, 4<<20) // several hash blocks
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	v := newVFS(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled: the hash must not run to completion
	if _, _, _, err := v.ChecksumCtx(ctx, "/big.bin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ChecksumCtx on a cancelled ctx = %v, want context.Canceled", err)
	}

	clean, algo, sum, err := v.ChecksumCtx(context.Background(), "/big.bin")
	if err != nil || algo != proto.AlgoSHA256 || clean != "/big.bin" {
		t.Fatalf("ChecksumCtx(bg) = (%q, %v, %v)", clean, algo, err)
	}
	if want := sha256.Sum256(data); sum != want {
		t.Fatal("checksum mismatch after a non-cancelled compute")
	}
}
