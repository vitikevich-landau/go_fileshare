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

// HandshakeMaxPayload caps a frame accepted before authentication. It is large
// enough for HELLO/AUTH_REQUEST/PING but far below MaxControlPayload, so an
// unauthenticated peer cannot make the server allocate megabytes per connection
// (CR-05).
const HandshakeMaxPayload = MaxStringLen + 256

// maxControlPayload bounds the ordinary control messages (those carrying at most
// one length-prefixed string plus small fixed fields).
const maxControlPayload = MaxStringLen + 256

// maxPayloadFor returns the largest legitimate payload for a message type, so
// the reader can reject an oversize length BEFORE allocating (CR-05). Only the
// genuinely large server->client messages get the full 4 MiB ceiling.
func maxPayloadFor(typ Msg) uint32 {
	switch typ {
	case MsgListDirResponse, MsgAdminConfig, MsgAdminClients:
		return MaxControlPayload
	case MsgChunkData:
		return ChunkSize + 64
	default:
		return maxControlPayload
	}
}

// ReadFrame reads one frame from r. On a clean connection close at a frame
// boundary it returns io.EOF. A malformed frame (unknown type or oversize
// payload for its type) returns a non-EOF error; the caller tears down only
// that connection (docs/tz/09-go-port.md §4.1).
func ReadFrame(r io.Reader) (Msg, []byte, error) {
	return ReadFrameLimited(r, MaxControlPayload)
}

// ReadFrameLimited is ReadFrame with an additional caller-supplied payload
// ceiling (used to keep pre-auth frames small).
func ReadFrameLimited(r io.Reader, limit uint32) (Msg, []byte, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err // io.EOF at the boundary is a clean close
	}
	typ := Msg(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:5])
	if !typ.Known() {
		return 0, nil, fmt.Errorf("proto: unknown msg type 0x%02x", hdr[0])
	}
	max := maxPayloadFor(typ)
	if limit < max {
		max = limit
	}
	if n > max {
		return 0, nil, fmt.Errorf("proto: %s payload %d exceeds max %d", typ, n, max)
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
