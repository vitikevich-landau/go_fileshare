package client

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestDownloadAcceptsCRC32 covers RR-2: a CRC32 DONE (first 4 bytes of the
// checksum field, big-endian) from a C++-compatible server is accepted.
func TestDownloadAcceptsCRC32(t *testing.T) {
	data := bytes.Repeat([]byte{0x5A}, 900)
	crc := crc32.ChecksumIEEE(data)

	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		serverHandshake(t, c2)
		scriptRead(t, c2, proto.MsgDownloadRequest)
		scriptWrite(t, c2, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		scriptWrite(t, c2, proto.ChunkData{TransferID: 1, Data: data})
		var cs [proto.ChecksumLen]byte
		binary.BigEndian.PutUint32(cs[:4], crc)
		scriptWrite(t, c2, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoCRC32, Checksum: cs})
	}()

	c, err := handshake(c1, Options{Login: "x"})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := c.Download("/f", dst, nil); err != nil {
		t.Fatalf("valid CRC32 download rejected: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, data) {
		t.Fatalf("crc32 download mismatch: %d bytes", len(got))
	}
}

func TestDownloadRejectsBadCRC32(t *testing.T) {
	data := bytes.Repeat([]byte{0x11}, 400)
	downloadShouldFail(t, func(conn net.Conn) {
		scriptWrite(t, conn, proto.DownloadAccept{TransferID: 1, TotalSize: uint64(len(data))})
		scriptWrite(t, conn, proto.ChunkData{TransferID: 1, Data: data})
		var cs [proto.ChecksumLen]byte
		binary.BigEndian.PutUint32(cs[:4], crc32.ChecksumIEEE(data)+1) // wrong CRC
		scriptWrite(t, conn, proto.DownloadDone{TransferID: 1, Algo: proto.AlgoCRC32, Checksum: cs})
	}, "bad crc32")
}
