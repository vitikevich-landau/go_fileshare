package server_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestDownloadCancelDuringRateLimitWait covers R3-1: a cancel that lands while
// the stream is blocked inside the rate limiter must wake that wait and end the
// download promptly, instead of hanging until the (possibly minutes-long) wait
// for one chunk completes.
func TestDownloadCancelDuringRateLimitWait(t *testing.T) {
	// 4 KiB/s: the first (burst-sized) chunk goes out immediately, then the
	// second chunk's rate-limit wait takes ~16 s — long enough that a cancel
	// which is NOT woken would visibly hang.
	e := newEnv(t, func(s *config.Settings) { s.Limits.PerClientBps = 4 * 1024 })
	makeFile(t, filepath.Join(e.share, "slow.bin"), 256*1024)

	c := dialNoAuth(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(250 * time.Millisecond) // first chunk flows, then the stream blocks in Wait
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		done <- c.DownloadCtx(ctx, "/slow.bin", filepath.Join(t.TempDir(), "out.bin"), nil)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled download returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("download did not return after cancel — the cancel is stuck in the rate-limit wait (R3-1)")
	}

	// The terminal CANCELLED frame must have left the connection usable.
	if _, _, lerr := c.ListDir("/"); lerr != nil {
		t.Fatalf("connection desynced after cancel: %v", lerr)
	}
}

// TestCancelWrongTransferIDIgnored covers R3-2: a DOWNLOAD_CANCEL whose transfer
// id does not match the active transfer must be ignored, so a stray or late
// cancel cannot abort the wrong one.
func TestCancelWrongTransferIDIgnored(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.PerClientBps = 256 * 1024 }) // slow enough to interleave a cancel
	const size = 256 * 1024
	want := makeFile(t, filepath.Join(e.share, "big2.bin"), size)

	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rawHandshakeNoAuth(t, conn)

	if _, err := conn.Write(proto.Encode(proto.DownloadRequest{Path: "/big2.bin"})); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := proto.ReadFrame(conn)
	if err != nil || typ != proto.MsgDownloadAccept {
		t.Fatalf("expected ACCEPT: typ=%s err=%v", typ, err)
	}
	am, _ := proto.Decode(typ, payload)
	tid := am.(proto.DownloadAccept).TransferID

	// A cancel for a different transfer id must not touch this one.
	if _, err := conn.Write(proto.Encode(proto.DownloadCancel{TransferID: tid + 12345})); err != nil {
		t.Fatal(err)
	}

	var got []byte
	for {
		typ, payload, err := proto.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		m, derr := proto.Decode(typ, payload)
		if derr != nil {
			t.Fatalf("decode: %v", derr)
		}
		switch v := m.(type) {
		case proto.ChunkData:
			got = append(got, v.Data...)
		case proto.DownloadDone:
			if !bytes.Equal(got, want) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), size)
			}
			return
		case proto.Error:
			t.Fatalf("transfer aborted by a mismatched-id cancel (R3-2): %s", v.Code)
		default:
			t.Fatalf("unexpected frame %s", typ)
		}
	}
}
