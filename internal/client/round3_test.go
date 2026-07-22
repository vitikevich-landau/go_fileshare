package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestDownloadLocalErrorDropsConn covers R3-3: a local failure after ACCEPT
// (here the ".part" path is a directory, so it cannot be opened for writing)
// must drop the connection rather than leave the server's streamed chunks
// buffered for a later request to misread, and must never publish the file.
func TestDownloadLocalErrorDropsConn(t *testing.T) {
	c1, c2 := net.Pipe()
	data := bytes.Repeat([]byte{0x5A}, 4096)
	sum := sha256.Sum256(data)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		scriptWrite(t, c2, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		// Keep streaming; the client should have dropped the connection, so these
		// writes error out and we stop.
		var cs [proto.ChecksumLen]byte
		copy(cs[:], sum[:])
		for i := 0; i < 128; i++ {
			if _, err := c2.Write(proto.Encode(proto.ChunkData{TransferID: 1, Data: data})); err != nil {
				return
			}
		}
		_, _ = c2.Write(proto.Encode(proto.DownloadDone{TransferID: 1, Algo: proto.AlgoSHA256, Checksum: cs}))
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.bin")
	// Make the ".part" path a directory so opening it for writing fails.
	if err := os.Mkdir(dst+".part", 0o755); err != nil {
		t.Fatal(err)
	}

	if derr := c.DownloadCtx(context.Background(), "/f", dst, nil); derr == nil {
		t.Fatal("download onto a directory .part should fail")
	}

	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("connection was not dropped after a local error (R3-3)")
	}

	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatal("published file despite a local failure")
	}
}

// TestDownloadFramingErrorDropsConn covers R3-3: a framing error mid-download
// (here an unknown message type) is detected after the 5-byte header is consumed
// but before its payload, leaving the stream desynced. The client must drop the
// connection rather than return a reusable-but-desynced socket.
func TestDownloadFramingErrorDropsConn(t *testing.T) {
	c1, c2 := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		scriptWrite(t, c2, proto.DownloadAccept{TransferID: 1, TotalSize: 4096})
		// A frame header with an unknown type: ReadFrame reads the 5-byte header,
		// rejects the type, and returns an error without consuming the payload.
		var hdr [5]byte
		hdr[0] = 0xFF
		binary.BigEndian.PutUint32(hdr[1:], 8)
		if _, err := c2.Write(hdr[:]); err != nil {
			return
		}
		// Further writes must fail once the client has dropped the connection.
		for i := 0; i < 64; i++ {
			if _, err := c2.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
				return
			}
		}
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if derr := c.DownloadCtx(context.Background(), "/f", dst, nil); derr == nil {
		t.Fatal("a framing error mid-download should fail")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("connection not dropped after a framing error (R3-3)")
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatal("published file despite a framing error")
	}
}

// TestPollEventsPartialFrameNoDesync covers R3-7: when a frame is delivered
// split with a gap longer than the poll timeout, PollEvents must not lose the
// already-read bytes. The deadline applies only until the first byte; the rest
// is read to completion, so the frame is received intact and the stream stays
// aligned for the next poll.
func TestPollEventsPartialFrameNoDesync(t *testing.T) {
	c1, c2 := net.Pipe()

	first := proto.Encode(proto.EventNotice{Severity: proto.SevInfo, Text: "split"})
	second := proto.Encode(proto.EventNotice{Severity: proto.SevWarn, Text: "whole"})

	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		// Send the first frame's opening byte, then stall past the poll timeout,
		// then the remainder — a gap that the old whole-frame deadline would have
		// misread as "no event", desyncing the stream.
		if _, err := c2.Write(first[:1]); err != nil {
			return
		}
		time.Sleep(1 * time.Second)
		if _, err := c2.Write(first[1:]); err != nil {
			return
		}
		// A second, whole frame to prove the stream stayed aligned.
		if _, err := c2.Write(second); err != nil {
			return
		}
	}()

	var got []proto.Message
	c, err := handshake(c1, Options{Login: "x", EventHandler: func(m proto.Message) { got = append(got, m) }})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Poll timeout (500ms) is shorter than the mid-frame gap (1s): the first byte
	// arrives in time, then the read blocks (no deadline) for the remainder.
	received, err := c.PollEvents(500 * time.Millisecond)
	if err != nil || !received {
		t.Fatalf("PollEvents (split frame) = (%v, %v), want (true, nil)", received, err)
	}
	received, err = c.PollEvents(time.Second)
	if err != nil || !received {
		t.Fatalf("PollEvents (second frame) = (%v, %v), want (true, nil)", received, err)
	}

	if len(got) != 2 {
		t.Fatalf("handler saw %d events, want 2", len(got))
	}
	if n0, ok := got[0].(proto.EventNotice); !ok || n0.Text != "split" {
		t.Fatalf("event 0 = %#v, want EventNotice{split}", got[0])
	}
	if n1, ok := got[1].(proto.EventNotice); !ok || n1.Text != "whole" {
		t.Fatalf("event 1 = %#v, want EventNotice{whole}", got[1])
	}
	c.Close()
}
