package domain

import "time"

// UnixMillis — момент времени в том виде, в каком его хранит серверная БД:
// Unix epoch milliseconds UTC, тип INTEGER, имя колонки оканчивается на `_ms`
// (§6.1). RFC3339 в базе не хранится нигде.
//
// Тип существует ради одной ошибки, которую §6.1 запрещает, а язык сам по себе
// не ловит: случайно забинденный time.Time. В обычной rowid-таблице он молча
// ложится в INTEGER-колонку как TEXT (проверено на всех трёх драйверах-
// кандидатах, ADR 0001 §3.7); механическую защиту в БД даёт STRICT, а здесь —
// то, что поля структур объявлены UnixMillis, а не time.Time.
type UnixMillis int64

// NowMillis возвращает текущий момент в кодировке §6.1.
func NowMillis() UnixMillis { return ToMillis(time.Now()) }

// ToMillis переводит момент времени в кодировку §6.1.
func ToMillis(t time.Time) UnixMillis { return UnixMillis(t.UnixMilli()) }

// Time возвращает момент времени в UTC.
func (ms UnixMillis) Time() time.Time { return time.UnixMilli(int64(ms)).UTC() }

// Add сдвигает момент на d с точностью до миллисекунды.
func (ms UnixMillis) Add(d time.Duration) UnixMillis {
	return ms + UnixMillis(d.Milliseconds())
}

// String печатает момент в RFC3339 с миллисекундами — для логов и сообщений об
// ошибках. В БД этот вид не попадает никогда (§6.1).
func (ms UnixMillis) String() string { return ms.Time().Format("2006-01-02T15:04:05.000Z07:00") }
