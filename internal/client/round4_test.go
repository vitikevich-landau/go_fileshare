package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestPollEventsStalledFrameBounded covers R4-1: a peer that sends one byte of a
// frame then stalls without closing the socket must not wedge the idle poll (and
// clientMu) forever. After the bounded frame timeout PollEvents errors and drops
// the connection instead of blocking indefinitely.
func TestPollEventsStalledFrameBounded(t *testing.T) {
	old := frameReadTimeout
	frameReadTimeout = 150 * time.Millisecond
	defer func() { frameReadTimeout = old }()

	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		// One byte of a frame, then stall: never send the rest, never close.
		_, _ = c2.Write([]byte{byte(proto.MsgEventNotice)})
		time.Sleep(2 * time.Second)
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	start := time.Now()
	received, perr := c.PollEvents(100 * time.Millisecond)
	if received || perr == nil {
		t.Fatalf("PollEvents on a stalled frame = (%v, %v), want (false, err)", received, perr)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("PollEvents blocked %v on a stalled frame, want bounded ~%v (R4-1)", elapsed, frameReadTimeout)
	}
	// The connection must have been dropped: a further poll errors, not idle-nil.
	if _, perr2 := c.PollEvents(50 * time.Millisecond); perr2 == nil {
		t.Fatal("connection not dropped after a stalled mid-frame read (R4-1)")
	}
}

// TestDownloadCancelBeforeAccept covers R4-2: if the server accepts the request
// but never sends DOWNLOAD_ACCEPT, cancelling ctx must still abort the download
// promptly (by dropping the connection), not hang forever in the ACCEPT wait.
func TestDownloadCancelBeforeAccept(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		time.Sleep(3 * time.Second) // never send ACCEPT
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		done <- c.DownloadCtx(ctx, "/f", filepath.Join(t.TempDir(), "out.bin"), nil)
	}()
	select {
	case derr := <-done:
		if !errors.Is(derr, context.Canceled) {
			t.Fatalf("cancel before ACCEPT returned %v, want context.Canceled", derr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DownloadCtx did not return after a cancel before ACCEPT (R4-2)")
	}
}

// TestDownloadAlreadyCancelledCtx covers R4-2: a ctx that is already cancelled
// makes DownloadCtx return context.Canceled without even sending a request.
func TestDownloadAlreadyCancelledCtx(t *testing.T) {
	c1, c2 := net.Pipe()
	sentReq := make(chan struct{})
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		_ = c2.SetReadDeadline(time.Now().Add(time.Second))
		var hdr [5]byte
		if _, err := io.ReadFull(c2, hdr[:]); err == nil {
			close(sentReq) // any frame after auth means a request was sent
		}
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	derr := c.DownloadCtx(ctx, "/f", filepath.Join(t.TempDir(), "out.bin"), nil)
	if !errors.Is(derr, context.Canceled) {
		t.Fatalf("already-cancelled download returned %v, want context.Canceled", derr)
	}
	select {
	case <-sentReq:
		t.Fatal("client sent a request despite an already-cancelled ctx (R4-2)")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDownloadStaleOffsetRetriesOnce covers R4-4: a server that always answers
// UNSUPPORTED_OFFSET must trigger exactly one retry (from offset 0) and then
// surface the error, never recurse forever.
func TestDownloadStaleOffsetRetriesOnce(t *testing.T) {
	c1, c2 := net.Pipe()
	var requests int32
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		for {
			typ, payload, err := proto.ReadFrame(c2)
			if err != nil || typ != proto.MsgDownloadRequest {
				return
			}
			_, _ = proto.Decode(typ, payload)
			atomic.AddInt32(&requests, 1)
			if _, err := c2.Write(proto.Encode(proto.Error{Code: proto.ErrUnsupportedOffset, Message: "stale"})); err != nil {
				return
			}
		}
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer c.Close()

	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(dst+".part", []byte("partial-data"), 0o644); err != nil { // offset > 0
		t.Fatal(err)
	}

	derr := c.DownloadCtx(context.Background(), "/f", dst, nil)
	if derr == nil {
		t.Fatal("a persistent UNSUPPORTED_OFFSET should surface an error, not loop")
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Fatalf("server saw %d DOWNLOAD_REQUESTs, want exactly 2 (one bounded retry) (R4-4)", n)
	}
}
