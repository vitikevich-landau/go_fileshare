package client

import (
	"net"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func TestHandshakeTimesOutOnSilentServer(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		scriptRead(t, c2, proto.MsgHello)
		time.Sleep(2 * time.Second) // never send HELLO_OK
	}()

	start := time.Now()
	_, err := handshake(c1, Options{Login: "x", DialTimeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("expected the handshake to time out against a silent server")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("handshake did not time out promptly: %v", el)
	}
}

func TestHandshakeRejectsExcessiveIters(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		scriptRead(t, c2, proto.MsgHello)
		scriptWrite(t, c2, proto.HelloOk{
			ProtoVer: proto.ProtoVersion, ServerName: "evil",
			AuthMode: proto.AuthChallenge, PBKDF2Iters: 4_000_000_000, // way over the cap
		})
	}()

	start := time.Now()
	_, err := handshake(c1, Options{Login: "x", Password: "pw", DialTimeout: 2 * time.Second})
	if err == nil {
		t.Fatal("expected rejection of an excessive iteration count")
	}
	// Must reject before running PBKDF2 (which for 4e9 iters would take minutes).
	if el := time.Since(start); el > time.Second {
		t.Fatalf("client appears to have run PBKDF2 despite bad iters: %v", el)
	}
}

func TestHandshakeRejectsZeroIters(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		scriptRead(t, c2, proto.MsgHello)
		scriptWrite(t, c2, proto.HelloOk{ProtoVer: proto.ProtoVersion, AuthMode: proto.AuthChallenge, PBKDF2Iters: 0})
	}()
	if _, err := handshake(c1, Options{Login: "x", Password: "pw", DialTimeout: time.Second}); err == nil {
		t.Fatal("expected rejection of a zero iteration count")
	}
}
