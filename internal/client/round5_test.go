package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestChecksumMismatchCancels covers R5-1: the local checksum verification is
// ctx-aware, so a cancel during hashing of a large .part aborts promptly with
// context.Canceled instead of reading the whole file.
func TestChecksumMismatchCancels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.part")
	if err := os.WriteFile(p, make([]byte, 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled: the hash must not run to completion

	var want [proto.ChecksumLen]byte
	if _, err := checksumMismatch(ctx, p, proto.AlgoSHA256, want); !errors.Is(err, context.Canceled) {
		t.Fatalf("checksumMismatch(sha256) on a cancelled ctx = %v, want context.Canceled", err)
	}
	if _, err := checksumMismatch(ctx, p, proto.AlgoCRC32, want); !errors.Is(err, context.Canceled) {
		t.Fatalf("checksumMismatch(crc32) on a cancelled ctx = %v, want context.Canceled", err)
	}
}

// TestDownloadCancelDuringLocalVerify covers R5-1 end-to-end: a cancel that
// lands after DOWNLOAD_DONE (while the client re-hashes the .part) must return
// context.Canceled, must NOT publish the file, and must keep the .part for a
// later resume — while leaving the connection in sync (the DONE is fully read).
func TestDownloadCancelDuringLocalVerify(t *testing.T) {
	c1, c2 := net.Pipe()
	data := make([]byte, 16<<20) // large enough that the local re-hash spans the cancel
	for i := range data {
		data[i] = byte(i * 13)
	}
	sum := sha256.Sum256(data)

	doneSent := make(chan struct{})
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		scriptWrite(t, c2, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		const chunk = 64 << 10
		for off := 0; off < len(data); off += chunk {
			end := off + chunk
			if end > len(data) {
				end = len(data)
			}
			scriptWrite(t, c2, proto.ChunkData{TransferID: 1, Data: data[off:end]})
		}
		var cs [proto.ChecksumLen]byte
		copy(cs[:], sum[:])
		scriptWrite(t, c2, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoSHA256, Checksum: cs})
		close(doneSent)
		// The client's watcher sends a late DOWNLOAD_CANCEL on cancel; consume it
		// so its write unblocks and DownloadCtx can return (and the wire is clean).
		_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, _ = proto.ReadFrame(c2)
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-doneSent // DONE is read; the client is entering the local verify
		cancel()
	}()

	dst := filepath.Join(t.TempDir(), "out.bin")
	done := make(chan error, 1)
	go func() { done <- c.DownloadCtx(ctx, "/f", dst, nil) }()
	select {
	case derr := <-done:
		if !errors.Is(derr, context.Canceled) {
			t.Fatalf("cancel during local verify returned %v, want context.Canceled", derr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DownloadCtx hung on a cancel during local verify (R5-1)")
	}

	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatal("published the file despite a cancel during verification")
	}
	if _, statErr := os.Stat(dst + ".part"); statErr != nil {
		t.Fatalf(".part must be kept for resume after a verification cancel: %v", statErr)
	}
}
