package proto

import (
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"testing"
)

// roundTrip encodes m to a frame, reads the frame back, decodes it, and checks
// the decoded message equals the original.
func roundTrip(t *testing.T, m Message) {
	t.Helper()
	frame := Encode(m)

	typ, payload, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame(%T): %v", m, err)
	}
	if typ != m.Type() {
		t.Fatalf("%T: type = 0x%02x, want 0x%02x", m, byte(typ), byte(m.Type()))
	}
	got, err := Decode(typ, payload)
	if err != nil {
		t.Fatalf("Decode(%T): %v", m, err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("%T round-trip mismatch:\n got  %#v\n want %#v", m, got, m)
	}
}

func TestRoundTripAllMessages(t *testing.T) {
	chal := [ChallengeLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	proof := [ProofLen]byte{}
	for i := range proof {
		proof[i] = byte(i * 3)
	}
	sum := [ChecksumLen]byte{}
	for i := range sum {
		sum[i] = byte(255 - i)
	}
	entry := DirEntry{Name: "файл с пробелом.txt", Kind: KindFile, Size: 123456789, Mtime: 1752537600, Flags: FlagNew}
	dir := DirEntry{Name: "sub dir", Kind: KindDir, Size: 0, Mtime: 42, Flags: 0}

	msgs := []Message{
		Error{Code: ErrAccessDenied, Message: "nope"},
		Ping{},
		Pong{},
		Hello{ProtoVer: ProtoVersion, ClientName: "go-commander/0.1"},
		HelloOk{ProtoVer: ProtoVersion, ServerName: "fshared", AuthMode: AuthChallenge, Challenge: chal, PBKDF2Iters: 200000},
		AuthRequest{Login: "vit", Proof: proof},
		AuthOk{Role: RoleAdmin, SessionID: 0xDEADBEEFCAFE, Motd: "welcome"},
		AuthFail{Reason: AuthFailBadCredentials, Message: "bad login or password"},
		ListDirRequest{Path: "/some/dir"},
		ListDirResponse{Path: "/some/dir", Entries: []DirEntry{dir, entry}},
		StatRequest{Path: "/x"},
		StatResponse{Path: "/x", Entry: entry},
		ChecksumRequest{Path: "/big.bin"},
		ChecksumResponse{Path: "/big.bin", Algo: AlgoSHA256, Checksum: sum},
		DownloadRequest{Path: "/big.bin", Offset: 1 << 40},
		DownloadAccept{TransferID: 7, TotalSize: 1 << 40},
		ChunkData{TransferID: 7, Data: []byte("some raw chunk bytes \x00\x01\x02")},
		DownloadDone{TransferID: 7, Algo: AlgoCRC32, Checksum: sum},
		DownloadCancel{TransferID: 7},
		Subscribe{Mask: SubFS | SubConfig},
		EventFs{Op: FsCreated, Kind: KindFile, Path: "/new.txt", Size: 10, Mtime: 1752537600},
		EventNotice{Severity: SevWarn, Text: "server going down"},
		EventConfig{Key: "limits.per_client_bps", NewValue: "5000000"},
		AdminGetConfig{},
		AdminConfig{JSON: []byte(`{"server":{"port":5555}}`)},
		AdminSet{Key: "limits.global_bps", Value: "10000000"},
		AdminSetResult{OK: true, Message: "applied"},
		AdminListClients{},
		AdminClients{Clients: []ClientInfo{
			{SessionID: 1, Login: "vit", IP: "10.0.0.2", Role: RoleAdmin, CurrentPath: "/big.bin", BytesSent: 999, SpeedBps: 5000000},
			{SessionID: 2, Login: "guest", IP: "10.0.0.3", Role: RoleUser, CurrentPath: "", BytesSent: 0, SpeedBps: 0},
		}},
		AdminKick{SessionID: 2},
		AdminKickResult{OK: false, Message: "no such session"},
		AdminStats{},
		AdminStatsResponse{UptimeS: 3600, BytesSent: 1 << 30, Completed: 12, ActiveConns: 3, ActiveDownloads: 1, SharedFiles: 100, PerClientBps: 5000000, GlobalBps: 0, Version: "go-2.0"},
		AdminShutdown{GraceSeconds: 90},
		AdminShutdownResult{OK: true, Message: "draining"},
	}
	for _, m := range msgs {
		roundTrip(t, m)
	}
}

func TestEmptyListRoundTrip(t *testing.T) {
	roundTrip(t, ListDirResponse{Path: "/", Entries: []DirEntry{}})
	roundTrip(t, AdminClients{Clients: []ClientInfo{}})
}

func TestReadFrameCleanCloseAtBoundary(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader(nil))
	if err != io.EOF {
		t.Fatalf("empty stream: err = %v, want io.EOF", err)
	}
}

func TestReadFrameUnknownType(t *testing.T) {
	// 0x01 was a v1 code, deliberately not reused in v2.
	frame := []byte{0x01, 0, 0, 0, 0}
	if _, _, err := ReadFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("expected error for unknown msg type")
	}
}

func TestReadFrameOversizePayload(t *testing.T) {
	var hdr [5]byte
	hdr[0] = byte(MsgListDirResponse)
	binary.BigEndian.PutUint32(hdr[1:], MaxControlPayload+1)
	if _, _, err := ReadFrame(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected error for oversize payload")
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	// Header promises 100 bytes but only 3 follow.
	var hdr [5]byte
	hdr[0] = byte(MsgListDirRequest)
	binary.BigEndian.PutUint32(hdr[1:], 100)
	buf := append(hdr[:], 1, 2, 3)
	_, _, err := ReadFrame(bytes.NewReader(buf))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated payload: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestDecodeTrailingBytes(t *testing.T) {
	// A valid Ping payload is empty; add a stray byte.
	if _, err := Decode(MsgPing, []byte{0x00}); err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestDecodeShortPayload(t *testing.T) {
	// DOWNLOAD_REQUEST needs path:str + offset:u64; give a truncated string len.
	if _, err := Decode(MsgDownloadRequest, []byte{0x00}); err == nil {
		t.Fatal("expected short-buffer error")
	}
}

func TestDecodeStringTooLong(t *testing.T) {
	// LIST_DIR_REQUEST path with a declared length above MaxPathLen.
	var w writer
	w.u16(MaxPathLen + 1) // length prefix over the cap
	// pad with that many bytes so only the length check trips
	pad := make([]byte, MaxPathLen+1)
	w.raw(pad)
	if _, err := Decode(MsgListDirRequest, w.buf); err == nil {
		t.Fatal("expected error for over-long path string")
	}
}

func TestDecodeListCountOverMax(t *testing.T) {
	var w writer
	w.str("/") // path
	w.u32(MaxListEntries + 1)
	if _, err := Decode(MsgListDirResponse, w.buf); err == nil {
		t.Fatal("expected error for list count over MaxListEntries")
	}
}

func TestChunkDataRawBytesPreserved(t *testing.T) {
	// Ensure raw chunk bytes are not length-prefixed or altered.
	data := bytes.Repeat([]byte{0xAB}, ChunkSize)
	frame := Encode(ChunkData{TransferID: 42, Data: data})
	_, payload, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(MsgChunkData, payload)
	if err != nil {
		t.Fatal(err)
	}
	cd := m.(ChunkData)
	if cd.TransferID != 42 || !bytes.Equal(cd.Data, data) {
		t.Fatalf("chunk data mismatch: id=%d len=%d", cd.TransferID, len(cd.Data))
	}
}

func TestKnownRejectsUnassignedCodes(t *testing.T) {
	for _, c := range []Msg{0x00, 0x01, 0x05, 0x09, 0x0F, 0x15, 0x26, 0x35, 0x44, 0x5E, 0xFF} {
		if c.Known() {
			t.Errorf("Msg 0x%02x should be unknown", byte(c))
		}
	}
}
