package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ─────────────────────────────────────────────────────────────────────────────
// codec.go — низкоуровневые кирпичики сериализации: чтение и запись примитивов в
// big-endian с ПРОВЕРКОЙ ГРАНИЦ. Здесь нет знания о конкретных сообщениях —
// только «прочитай u32», «запиши строку с префиксом длины». messages.go
// собирает из этих кирпичиков разбор/сборку каждого сообщения.
//
// Главный принцип: получатель НИКОГДА не доверяет входным байтам. Любое чтение
// сначала проверяет, что нужное число байт реально есть (need), и возвращает
// ошибку вместо паники. Так битый или враждебный кадр рвёт одно соединение, а не
// роняет процесс (docs/tz/09-go-port.md §5.1).
// ─────────────────────────────────────────────────────────────────────────────

// ErrShort возвращается, когда тело обрезано (чтение вышло бы за конец буфера).
// Вызывающий трактует любую ошибку декодирования как «битый кадр» и рвёт только
// это соединение.
var ErrShort = errors.New("proto: short buffer")

// reader — курсор по телу сообщения с проверкой границ. Каждый аксессор при
// нехватке байт возвращает ошибку, а не паникует (docs/tz/09-go-port.md §5.1).
type reader struct {
	b []byte // всё тело
	i int    // сколько уже прочитано (позиция курсора)
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

// take возвращает КОПИЮ следующих n байт. Именно копию (а не под-срез тела),
// чтобы вызывающий мог хранить её и после того, как буфер тела переиспользуют.
func (r *reader) take(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, r.b[r.i:r.i+n])
	r.i += n
	return out, nil
}

// str читает строку с префиксом длины u16, отвергая длину больше max.
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

// fixedInto читает ровно len(dst) байт в dst (для полей фиксированной длины:
// challenge, proof, checksum).
func (r *reader) fixedInto(dst []byte) error {
	if err := r.need(len(dst)); err != nil {
		return err
	}
	copy(dst, r.b[r.i:r.i+len(dst)])
	r.i += len(dst)
	return nil
}

// rest возвращает копию всех оставшихся байт (используется в CHUNK_DATA, где
// длину данных задаёт граница кадра, а не префикс).
func (r *reader) rest() []byte {
	out := make([]byte, r.remaining())
	copy(out, r.b[r.i:])
	r.i = len(r.b)
	return out
}

// end проверяет, что тело израсходовано ПОЛНОСТЬЮ. Зеркалит require_end из
// эталона на C++: «хвост» лишних байт означает несовпадение формата
// (docs/tz/09-go-port.md §5.1).
func (r *reader) end() error {
	if r.remaining() != 0 {
		return fmt.Errorf("proto: %d trailing bytes", r.remaining())
	}
	return nil
}

// writer накапливает тело сообщения в проводном порядке байт (big-endian).
type writer struct {
	buf []byte
}

func (w *writer) u8(v uint8)   { w.buf = append(w.buf, v) }
func (w *writer) u16(v uint16) { w.buf = binary.BigEndian.AppendUint16(w.buf, v) }
func (w *writer) u32(v uint32) { w.buf = binary.BigEndian.AppendUint32(w.buf, v) }
func (w *writer) u64(v uint64) { w.buf = binary.BigEndian.AppendUint64(w.buf, v) }

func (w *writer) raw(b []byte) { w.buf = append(w.buf, b...) }

// str пишет строку с префиксом длины u16. Слишком длинные строки обрезаются до
// MaxStringLen; значения контролирует вызывающий, так что это лишь защитный
// предохранитель.
func (w *writer) str(s string) {
	if len(s) > MaxStringLen {
		s = s[:MaxStringLen]
	}
	w.u16(uint16(len(s)))
	w.buf = append(w.buf, s...)
}

// fixed пишет ровно n байт: если b короче — дополняет нулями, если длиннее —
// обрезает. Так поля фиксированной длины всегда занимают ровно n байт.
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
