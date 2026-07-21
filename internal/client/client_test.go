package client

import (
	"bytes"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// scriptWrite sends a framed message on conn.
func scriptWrite(t *testing.T, conn net.Conn, m proto.Message) {
	t.Helper()
	if _, err := conn.Write(proto.Encode(m)); err != nil {
		t.Errorf("script write %T: %v", m, err)
	}
}

// scriptRead reads a frame and asserts its type, returning the decoded message.
func scriptRead(t *testing.T, conn net.Conn, want proto.Msg) proto.Message {
	t.Helper()
	typ, payload, err := proto.ReadFrame(conn)
	if err != nil {
		t.Fatalf("script read: %v", err)
	}
	if typ != want {
		t.Fatalf("script read type = %s, want %s", typ, want)
	}
	m, err := proto.Decode(typ, payload)
	if err != nil {
		t.Fatalf("script decode: %v", err)
	}
	return m
}

// TestDownloadHandlesEventMidStream verifies that an EVENT_FS delivered between
// CHUNK_DATA frames is routed to the handler without corrupting the download
// (docs/tz/09-go-port.md §8, "событие посреди закачки не портит поток").
func TestDownloadHandlesEventMidStream(t *testing.T) {
	c1, c2 := net.Pipe()

	part1 := bytes.Repeat([]byte{0xAA}, 1000)
	part2 := bytes.Repeat([]byte{0xBB}, 777)
	full := append(append([]byte{}, part1...), part2...)
	sum := sha256.Sum256(full)

	// Scripted server.
	go func() {
		defer c2.Close()
		scriptRead(t, c2, proto.MsgHello)
		scriptWrite(t, c2, proto.HelloOk{ProtoVer: proto.ProtoVersion, ServerName: "pipe", AuthMode: proto.AuthNone, PBKDF2Iters: 1000})
		scriptRead(t, c2, proto.MsgAuthRequest)
		scriptWrite(t, c2, proto.AuthOk{Role: proto.RoleAdmin, SessionID: 1})

		scriptRead(t, c2, proto.MsgDownloadRequest)
		scriptWrite(t, c2, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(full))})
		scriptWrite(t, c2, proto.ChunkData{TransferID: 1, Data: part1})
		// An out-of-band event lands between chunks.
		scriptWrite(t, c2, proto.EventFs{Op: proto.FsCreated, Kind: proto.KindFile, Path: "/incoming/new.txt", Size: 10, Mtime: 123})
		scriptWrite(t, c2, proto.ChunkData{TransferID: 1, Data: part2})
		var csum [proto.ChecksumLen]byte
		copy(csum[:], sum[:])
		scriptWrite(t, c2, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoSHA256, Checksum: csum})
	}()

	var events []proto.Message
	c, err := handshake(c1, Options{Login: "x", EventHandler: func(m proto.Message) {
		events = append(events, m)
	}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if c.Role() != proto.RoleAdmin {
		t.Fatalf("role = %v", c.Role())
	}

	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := c.Download("/f", dst, nil); err != nil {
		t.Fatalf("download: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("download corrupted: got %d bytes, want %d", len(got), len(full))
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 mid-stream event, got %d", len(events))
	}
	ev, ok := events[0].(proto.EventFs)
	if !ok || ev.Path != "/incoming/new.txt" {
		t.Fatalf("event = %#v, want EventFs /incoming/new.txt", events[0])
	}
}

// TestPollEventsReceivesAndTimesOut checks idle event polling.
func TestPollEventsReceivesAndTimesOut(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		scriptRead(t, c2, proto.MsgHello)
		scriptWrite(t, c2, proto.HelloOk{ProtoVer: proto.ProtoVersion, ServerName: "pipe", AuthMode: proto.AuthNone, PBKDF2Iters: 1000})
		scriptRead(t, c2, proto.MsgAuthRequest)
		scriptWrite(t, c2, proto.AuthOk{Role: proto.RoleUser, SessionID: 1})
		// Push one notice, then stay silent.
		scriptWrite(t, c2, proto.EventNotice{Severity: proto.SevInfo, Text: "hi"})
		time.Sleep(200 * time.Millisecond)
	}()

	var got []proto.Message
	c, err := handshake(c1, Options{Login: "x", EventHandler: func(m proto.Message) { got = append(got, m) }})
	if err != nil {
		t.Fatal(err)
	}
	received, err := c.PollEvents(time.Second)
	if err != nil || !received {
		t.Fatalf("PollEvents = (%v, %v), want (true, nil)", received, err)
	}
	if len(got) != 1 {
		t.Fatalf("handler saw %d events, want 1", len(got))
	}
	// No further events: should time out cleanly.
	received, err = c.PollEvents(50 * time.Millisecond)
	if err != nil || received {
		t.Fatalf("idle PollEvents = (%v, %v), want (false, nil)", received, err)
	}
	c.Close()
}
