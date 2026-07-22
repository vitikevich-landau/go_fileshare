package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func hdrClaiming(typ Msg, n uint32) []byte {
	var h [HeaderSize]byte
	h[0] = byte(typ)
	binary.BigEndian.PutUint32(h[1:], n)
	return h[:]
}

func TestReadFramePerTypeCap(t *testing.T) {
	// A control message (HELLO) claiming a 4 MiB payload is rejected by its
	// per-type cap before any allocation (CR-05).
	if _, _, err := ReadFrame(bytes.NewReader(hdrClaiming(MsgHello, MaxControlPayload))); err == nil {
		t.Fatal("oversize HELLO should be rejected by its per-type cap")
	}
	// CHUNK_DATA is capped at ~ChunkSize.
	if _, _, err := ReadFrame(bytes.NewReader(hdrClaiming(MsgChunkData, MaxControlPayload))); err == nil {
		t.Fatal("oversize CHUNK_DATA should be rejected")
	}
}

func TestReadFrameLimitedPreAuth(t *testing.T) {
	// A pre-auth read with the handshake cap rejects even a large-type header.
	if _, _, err := ReadFrameLimited(bytes.NewReader(hdrClaiming(MsgListDirResponse, MaxControlPayload)), HandshakeMaxPayload); err == nil {
		t.Fatal("pre-auth oversize frame should be rejected regardless of type")
	}
	// A normal small HELLO still passes the size gate.
	frame := Encode(Hello{ProtoVer: ProtoVersion, ClientName: "ok"})
	if _, _, err := ReadFrameLimited(bytes.NewReader(frame), HandshakeMaxPayload); err != nil {
		t.Fatalf("valid small HELLO rejected under handshake cap: %v", err)
	}
}
