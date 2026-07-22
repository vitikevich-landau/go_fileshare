package server_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestPreAuthOversizeFrameRejectedPromptly covers CR-05: an unauthenticated
// peer that sends a HELLO header claiming a 4 MiB payload must be rejected right
// away, not have the server block (allocating megabytes) waiting for a payload
// that never arrives.
func TestPreAuthOversizeFrameRejectedPromptly(t *testing.T) {
	e := newEnv(t, nil)
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A well-formed 5-byte header, claiming the maximum payload, and no payload.
	hdr := make([]byte, 5)
	hdr[0] = byte(proto.MsgHello)
	binary.BigEndian.PutUint32(hdr[1:], proto.MaxControlPayload)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}

	// The server should reject the oversize length and send a best-effort ERROR,
	// then close — well within the handshake timeout. Before the fix it would
	// block reading 4 MiB and this read would time out.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, _, err := proto.ReadFrame(conn)
	if err != nil {
		t.Fatalf("expected a prompt ERROR frame, got %v (server blocked on the oversize payload?)", err)
	}
	if typ != proto.MsgError {
		t.Fatalf("got %s, want ERROR", typ)
	}
}
