package client

import (
	"bytes"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// serverHandshake plays the server side of HELLO/AUTH (no-auth) over conn.
func serverHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	scriptRead(t, conn, proto.MsgHello)
	scriptWrite(t, conn, proto.HelloOk{ProtoVer: proto.ProtoVersion, ServerName: "pipe", AuthMode: proto.AuthNone, PBKDF2Iters: 1000})
	scriptRead(t, conn, proto.MsgAuthRequest)
	scriptWrite(t, conn, proto.AuthOk{Role: proto.RoleAdmin, SessionID: 1})
}

// downloadShouldFail runs a client download against a scripted server and
// asserts it fails and never publishes localPath.
func downloadShouldFail(t *testing.T, script func(conn net.Conn), what string) {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		script(c2)
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if derr := c.Download("/f", dst, nil); derr == nil {
		t.Fatalf("%s: download unexpectedly succeeded", what)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("%s: published file despite failure", what)
	}
}

func TestDownloadRejectsWrongTransferID(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 500)
	sum := sha256.Sum256(data)
	downloadShouldFail(t, func(conn net.Conn) {
		scriptWrite(t, conn, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		scriptWrite(t, conn, proto.ChunkData{TransferID: 1, Data: data})
		var cs [proto.ChecksumLen]byte
		copy(cs[:], sum[:])
		scriptWrite(t, conn, proto.DownloadDone{TransferID: 2, Algo: proto.AlgoSHA256, Checksum: cs}) // wrong id
	}, "wrong transfer id")
}

func TestDownloadRejectsShortRead(t *testing.T) {
	half := bytes.Repeat([]byte{0xCD}, 500)
	downloadShouldFail(t, func(conn net.Conn) {
		scriptWrite(t, conn, proto.DownloadAccept{TransferID: 1, TotalSize: 1000}) // announces 1000
		scriptWrite(t, conn, proto.ChunkData{TransferID: 1, Data: half})           // sends only 500
		var cs [proto.ChecksumLen]byte                                             // checksum of the half (irrelevant; caught by received!=total first)
		s := sha256.Sum256(half)
		copy(cs[:], s[:])
		scriptWrite(t, conn, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoSHA256, Checksum: cs})
	}, "short read")
}

func TestDownloadRejectsUnverifiableChecksum(t *testing.T) {
	data := bytes.Repeat([]byte{0xEF}, 700)
	downloadShouldFail(t, func(conn net.Conn) {
		scriptWrite(t, conn, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		scriptWrite(t, conn, proto.ChunkData{TransferID: 1, Data: data})
		// AlgoPending == "checksum not available": must be rejected, not published.
		scriptWrite(t, conn, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoPending})
	}, "pending checksum")
}
