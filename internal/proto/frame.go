package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame builds a complete on-the-wire frame (5-byte header + payload).
func Frame(typ Msg, payload []byte) []byte {
	out := make([]byte, HeaderSize+len(payload))
	out[0] = byte(typ)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[HeaderSize:], payload)
	return out
}

// ReadFrame reads one frame from r. On a clean connection close at a frame
// boundary it returns io.EOF. A malformed frame (unknown type or oversize
// payload) returns a non-EOF error; the caller tears down only that connection
// (docs/tz/09-go-port.md §4.1).
func ReadFrame(r io.Reader) (Msg, []byte, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err // io.EOF at the boundary is a clean close
	}
	typ := Msg(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:5])
	if !typ.Known() {
		return 0, nil, fmt.Errorf("proto: unknown msg type 0x%02x", hdr[0])
	}
	if n > MaxControlPayload {
		return 0, nil, fmt.Errorf("proto: payload %d exceeds max %d", n, MaxControlPayload)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF // truncated payload is not a clean close
		}
		return 0, nil, err
	}
	return typ, p, nil
}

// WriteFrame writes one framed message to w.
func WriteFrame(w io.Writer, typ Msg, payload []byte) error {
	_, err := w.Write(Frame(typ, payload))
	return err
}
