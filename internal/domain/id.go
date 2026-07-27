// Package domain — словарь предметной области облачного диска: идентификаторы,
// перечисления и их инварианты, объявленные в docs/tz/10-cloud-drive-spec.md
// §2.1 и §6.
//
// Пакет намеренно не знает ни про SQL, ни про протокол: он даёт типы, которыми
// одинаково пользуются репозитории метаданных (§6), сервисы (§7–§11) и кодеки
// v3 (§3). Отсюда два правила:
//
//   - каждый ЗАКРЫТЫЙ словарь §6 (тот, что в DDL выражен через CHECK … IN (…))
//     имеет здесь свой тип и метод Valid. Разъезд между этим перечнем и CHECK в
//     миграции 0001 ловится тестом, а не ревью;
//   - типы не несут поведения, зависящего от хранилища. Физический путь blob
//     выводится из ResourceID (§5.1), но живёт в слое storage, а не здесь.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// idHexLen — каноническая длина текстового представления идентификатора: 32
// символа нижнего регистра hex, то есть 128 бит (§2.1). Ровно в таком виде
// идентификатор хранится в TEXT-колонках §6 и записывается в пути §5.1; по
// проводу тот же идентификатор идёт фиксированными 16 байтами (§3.9).
const idHexLen = 32

// ResourceID — стабильный идентификатор файла или каталога (§2.1). Путь может
// измениться после rename/move, ResourceID — нет; он же является единственным
// источником физического пути blob (§5.1).
type ResourceID [16]byte

// UploadID — идентификатор одной незавершённой загрузки (§2.1, `uploads.id`).
type UploadID [16]byte

// TrashID — идентификатор записи корзины (§2.1, `trash_entries.id`). Это НЕ
// ResourceID удалённого объекта: одна и та же строка `resources` может побывать
// в корзине несколько раз, получая каждый раз новый TrashID. Разные типы здесь
// нужны именно для того, чтобы эти два идентификатора нельзя было перепутать
// молча — команды корзины (§18.3) принимают TrashID.
type TrashID [16]byte

// String возвращает каноническую форму — 32 символа нижнего регистра hex.
func (id ResourceID) String() string { return formatRawID(id) }

// String возвращает каноническую форму — 32 символа нижнего регистра hex.
func (id UploadID) String() string { return formatRawID(id) }

// String возвращает каноническую форму — 32 символа нижнего регистра hex.
func (id TrashID) String() string { return formatRawID(id) }

// IsZero сообщает, что идентификатор не заполнен. Нулевое значение формально
// является корректным hex, поэтому это признак «поле не установлено» в коде, а
// не признак невалидности: crypto/rand такого значения на практике не выдаёт.
func (id ResourceID) IsZero() bool { return id == ResourceID{} }

// IsZero сообщает, что идентификатор не заполнен (см. ResourceID.IsZero).
func (id UploadID) IsZero() bool { return id == UploadID{} }

// IsZero сообщает, что идентификатор не заполнен (см. ResourceID.IsZero).
func (id TrashID) IsZero() bool { return id == TrashID{} }

// NewResourceID выдаёт новый случайный идентификатор ресурса.
func NewResourceID() (ResourceID, error) {
	raw, err := newRawID()
	return ResourceID(raw), err
}

// NewUploadID выдаёт новый случайный идентификатор загрузки.
func NewUploadID() (UploadID, error) {
	raw, err := newRawID()
	return UploadID(raw), err
}

// NewTrashID выдаёт новый случайный идентификатор записи корзины.
func NewTrashID() (TrashID, error) {
	raw, err := newRawID()
	return TrashID(raw), err
}

// ParseResourceID разбирает каноническую форму (§2.1).
func ParseResourceID(s string) (ResourceID, error) {
	raw, err := parseRawID(s)
	return ResourceID(raw), err
}

// ParseUploadID разбирает каноническую форму (§2.1).
func ParseUploadID(s string) (UploadID, error) {
	raw, err := parseRawID(s)
	return UploadID(raw), err
}

// ParseTrashID разбирает каноническую форму (§2.1).
func ParseTrashID(s string) (TrashID, error) {
	raw, err := parseRawID(s)
	return TrashID(raw), err
}

// newRawID берёт 128 бит из crypto/rand. Ошибка генератора возвращается, а не
// подменяется предсказуемым значением: идентификатор задаёт физический путь
// (§5.1), и угадываемый ResourceID — это угадываемый путь.
func newRawID() ([16]byte, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return raw, fmt.Errorf("domain: generate id: %w", err)
	}
	return raw, nil
}

// formatRawID кодирует идентификатор в 32 символа нижнего регистра hex.
func formatRawID(raw [16]byte) string { return hex.EncodeToString(raw[:]) }

// parseRawID принимает ТОЛЬКО каноническую форму `^[0-9a-f]{32}$`. Верхний
// регистр отвергается явно: hex.Decode принял бы его молча, и тогда один и тот
// же идентификатор имел бы два текстовых представления — два разных значения
// TEXT PRIMARY KEY в §6 и два разных пути в §5.1.
func parseRawID(s string) ([16]byte, error) {
	var raw [16]byte
	if len(s) != idHexLen {
		return raw, fmt.Errorf("domain: id %q: want %d hex chars, got %d", s, idHexLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return raw, fmt.Errorf("domain: id %q: only lowercase hex is allowed", s)
		}
	}
	if _, err := hex.Decode(raw[:], []byte(s)); err != nil {
		return raw, fmt.Errorf("domain: id %q: %w", s, err)
	}
	return raw, nil
}
