package server_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// rawHandshakeNoAuth performs the no-auth handshake over a raw connection.
func rawHandshakeNoAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write(proto.Encode(proto.Hello{ProtoVer: proto.ProtoVersion, ClientName: "raw"})); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := proto.ReadFrame(conn); err != nil || typ != proto.MsgHelloOk {
		t.Fatalf("HELLO_OK: typ=%s err=%v", typ, err)
	}
	if _, err := conn.Write(proto.Encode(proto.AuthRequest{Login: "raw"})); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := proto.ReadFrame(conn); err != nil || typ != proto.MsgAuthOk {
		t.Fatalf("AUTH_OK: typ=%s err=%v", typ, err)
	}
}

// TestPartialFrameThenIdleClosesCleanly covers RR-1: a partial frame that stalls
// must not be misread as a new frame after an idle event. With no per-frame
// deadline, the read simply blocks and the idle watchdog closes the connection
// cleanly (EOF), never producing a garbage response.
func TestPartialFrameThenIdleClosesCleanly(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.IdleTimeoutS = 1 })
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rawHandshakeNoAuth(t, conn)

	// A LIST_DIR_REQUEST header promising a 100-byte payload, but only 3 bytes
	// of it are ever sent — the frame never completes.
	var hdr [5]byte
	hdr[0] = byte(proto.MsgListDirRequest)
	binary.BigEndian.PutUint32(hdr[1:], 100)
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{'/', 'a', 'b'}); err != nil {
		t.Fatal(err)
	}

	// The idle watchdog must close the connection; the client sees EOF, not a
	// spurious LIST_DIR_RESPONSE or a hang.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, _, rerr := proto.ReadFrame(conn)
	if rerr == nil {
		t.Fatalf("expected the connection to be closed on idle, got a %s frame", typ)
	}
}
