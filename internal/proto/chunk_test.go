package proto

import "testing"

// TestDecodeChunkDataBound verifies CHUNK_DATA is bounded to ChunkSize on decode
// (a conforming peer never exceeds it, but an oversize chunk must be rejected).
func TestDecodeChunkDataBound(t *testing.T) {
	var over writer
	over.u32(7)
	over.raw(make([]byte, ChunkSize+1))
	if _, err := Decode(MsgChunkData, over.buf); err == nil {
		t.Fatal("chunk data exceeding ChunkSize should be rejected")
	}

	var exact writer
	exact.u32(7)
	exact.raw(make([]byte, ChunkSize))
	if _, err := Decode(MsgChunkData, exact.buf); err != nil {
		t.Fatalf("exact-ChunkSize chunk rejected: %v", err)
	}
}
