package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame собирает готовый кадр для отправки: 5-байтовый заголовок
// (тип + длина тела) плюс само тело.
func Frame(typ Msg, payload []byte) []byte {
	out := make([]byte, HeaderSize+len(payload))
	out[0] = byte(typ)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[HeaderSize:], payload)
	return out
}

// HandshakeMaxPayload — потолок размера кадра, принимаемого ДО аутентификации.
// Его хватает на HELLO/AUTH_REQUEST/PING, но он много меньше MaxControlPayload,
// поэтому неаутентифицированный собеседник не может заставить сервер выделять
// мегабайты на соединение (CR-05).
const HandshakeMaxPayload = MaxStringLen + 256

// maxControlPayload ограничивает обычные управляющие сообщения (те, что несут
// максимум одну строку с префиксом длины плюс небольшие фиксированные поля).
const maxControlPayload = MaxStringLen + 256

// maxPayloadFor возвращает наибольший ДОПУСТИМЫЙ размер тела для данного типа
// сообщения, чтобы читатель отверг завышенную длину ЕЩЁ ДО выделения памяти
// (CR-05). Полный потолок 4 МиБ получают только по-настоящему большие
// сообщения сервер→клиент.
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

// ReadFrame читает один кадр из r. При ЧИСТОМ закрытии соединения на границе
// кадра возвращает io.EOF. Битый кадр (неизвестный тип или тело больше
// допустимого для этого типа) даёт не-EOF ошибку; вызывающий рвёт ТОЛЬКО это
// соединение, не трогая остальные (docs/tz/09-go-port.md §4.1).
func ReadFrame(r io.Reader) (Msg, []byte, error) {
	return ReadFrameLimited(r, MaxControlPayload)
}

// ReadFrameLimited — то же, что ReadFrame, но с дополнительным потолком на тело,
// который задаёт вызывающий (нужно, чтобы держать до-аутентификационные кадры
// маленькими).
func ReadFrameLimited(r io.Reader, limit uint32) (Msg, []byte, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err // io.EOF на границе кадра — это чистое закрытие
	}
	return readFramePayload(hdr, r, limit)
}

// ReadFrameContinue дочитывает кадр, первый байт заголовка которого уже прочитан
// в first, а затем берёт остаток заголовка и тело. Это позволяет вызывающему
// «подсмотреть» первый байт под дедлайном простоя, а как только кадр начался —
// дочитать его БЕЗ дедлайна. Так медленный или фрагментированный кадр никогда не
// остаётся прочитанным наполовину и не рассинхронизирует поток (R3-7).
func ReadFrameContinue(first byte, r io.Reader, limit uint32) (Msg, []byte, error) {
	var hdr [HeaderSize]byte
	hdr[0] = first
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF // оборванный заголовок — не чистое закрытие
		}
		return 0, nil, err
	}
	return readFramePayload(hdr, r, limit)
}

// readFramePayload проверяет уже прочитанный 5-байтовый заголовок и читает его
// тело в пределах limit. Общий код для ReadFrameLimited и ReadFrameContinue.
func readFramePayload(hdr [HeaderSize]byte, r io.Reader, limit uint32) (Msg, []byte, error) {
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
			err = io.ErrUnexpectedEOF // обрезанное тело — не чистое закрытие
		}
		return 0, nil, err
	}
	return typ, p, nil
}

// WriteFrame записывает один кадр в w.
func WriteFrame(w io.Writer, typ Msg, payload []byte) error {
	_, err := w.Write(Frame(typ, payload))
	return err
}
