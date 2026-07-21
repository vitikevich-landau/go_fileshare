package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShort is returned when a payload is truncated (a read would run past the
// end of the buffer). Callers treat any decode error as "malformed frame" and
// tear down only that connection.
var ErrShort = errors.New("proto: short buffer")

// reader is a bounds-checked cursor over a message payload. Every accessor
// returns an error on underflow rather than panicking (docs/tz/09-go-port.md §5.1).
type reader struct {
	b []byte
	i int
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) remaining() int { return len(r.b) - r.i }

func (r *reader) need(n int) error {
	if n < 0 || r.remaining() < n {
		return ErrShort
	}
	return nil
}

func (r *reader) u8() (uint8, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.b[r.i]
	r.i++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if err := r.need(2); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint16(r.b[r.i:])
	r.i += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(r.b[r.i:])
	r.i += 4
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(r.b[r.i:])
	r.i += 8
	return v, nil
}

// take returns a copy of the next n bytes. A copy (not a sub-slice of the
// payload) is returned so callers may retain it after the payload buffer is
// reused.
func (r *reader) take(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, r.b[r.i:r.i+n])
	r.i += n
	return out, nil
}

// str reads a u16-length-prefixed UTF-8 string, rejecting lengths above max.
func (r *reader) str(max int) (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	if int(n) > max {
		return "", fmt.Errorf("proto: string len %d exceeds max %d", n, max)
	}
	if err := r.need(int(n)); err != nil {
		return "", err
	}
	s := string(r.b[r.i : r.i+int(n)])
	r.i += int(n)
	return s, nil
}

// fixedInto reads exactly len(dst) bytes into dst.
func (r *reader) fixedInto(dst []byte) error {
	if err := r.need(len(dst)); err != nil {
		return err
	}
	copy(dst, r.b[r.i:r.i+len(dst)])
	r.i += len(dst)
	return nil
}

// rest returns a copy of all remaining bytes (used by CHUNK_DATA).
func (r *reader) rest() []byte {
	out := make([]byte, r.remaining())
	copy(out, r.b[r.i:])
	r.i = len(r.b)
	return out
}

// end asserts the payload was fully consumed. It mirrors require_end in the C++
// reference: trailing bytes indicate a format mismatch (docs/tz/09-go-port.md §5.1).
func (r *reader) end() error {
	if r.remaining() != 0 {
		return fmt.Errorf("proto: %d trailing bytes", r.remaining())
	}
	return nil
}

// writer accumulates a payload in big-endian wire order.
type writer struct {
	buf []byte
}

func (w *writer) u8(v uint8)   { w.buf = append(w.buf, v) }
func (w *writer) u16(v uint16) { w.buf = binary.BigEndian.AppendUint16(w.buf, v) }
func (w *writer) u32(v uint32) { w.buf = binary.BigEndian.AppendUint32(w.buf, v) }
func (w *writer) u64(v uint64) { w.buf = binary.BigEndian.AppendUint64(w.buf, v) }

func (w *writer) raw(b []byte) { w.buf = append(w.buf, b...) }

// str writes a u16-length-prefixed string. Over-long strings are clamped to
// MaxStringLen; callers control the values so this is a defensive backstop.
func (w *writer) str(s string) {
	if len(s) > MaxStringLen {
		s = s[:MaxStringLen]
	}
	w.u16(uint16(len(s)))
	w.buf = append(w.buf, s...)
}

// fixed writes exactly n bytes: b is zero-padded if short, truncated if long.
func (w *writer) fixed(b []byte, n int) {
	if len(b) >= n {
		w.buf = append(w.buf, b[:n]...)
		return
	}
	w.buf = append(w.buf, b...)
	for i := len(b); i < n; i++ {
		w.buf = append(w.buf, 0)
	}
}
