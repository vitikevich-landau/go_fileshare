package auth

import (
	"sync"
	"time"
)

// Guard тормозит подбор пароля, забанивая IP после слишком многих ПОДРЯД идущих
// неудачных попыток входа (docs/tz/09-go-port.md §5.3). Текущее время передаётся
// аргументом, чтобы поведение было детерминированным в тестах (не зовём
// time.Now() внутри). Безопасен для конкурентного использования.
type Guard struct {
	maxFails FailCount // после стольких неудач подряд — бан

	mu      sync.Mutex
	entries map[string]*guardEntry // ключ — ClientIP
}

// guardEntry — учёт по одному IP: сколько неудач подряд и до какого момента бан.
type guardEntry struct {
	fails    FailCount // неудачи подряд (сбрасывается при успехе или бане)
	banUntil time.Time // до этого момента IP забанен
}

// NewGuard возвращает Guard, который банит после maxFails неудач подряд
// (значение меньше 1 трактуется как 3).
func NewGuard(maxFails FailCount) *Guard {
	if maxFails < 1 {
		maxFails = 3
	}
	return &Guard{maxFails: maxFails, entries: map[string]*guardEntry{}}
}

// Banned сообщает, забанен ли ip прямо сейчас (по времени now).
func (g *Guard) Banned(ip ClientIP, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[ip]
	return e != nil && now.Before(e.banUntil)
}

// Fail фиксирует неудачную попытку с ip. Когда счётчик неудач достигает
// maxFails, ip банится на banDur (а счётчик сбрасывается). Возвращает, забанен ли
// ip теперь.
func (g *Guard) Fail(ip ClientIP, now time.Time, banDur time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[ip]
	if e == nil {
		e = &guardEntry{}
		g.entries[ip] = e
	}
	e.fails++
	if e.fails >= g.maxFails {
		e.banUntil = now.Add(banDur)
		e.fails = 0
		return true
	}
	return false
}

// Success сбрасывает накопленные неудачи для ip (успешный вход «прощает» историю).
func (g *Guard) Success(ip ClientIP) {
	g.mu.Lock()
	delete(g.entries, ip)
	g.mu.Unlock()
}

// Cleanup удаляет записи, у которых бан истёк и нет накопленных неудач, ограничивая
// память при постоянно меняющемся наборе клиентских IP (иначе карта только росла бы).
func (g *Guard) Cleanup(now time.Time) {
	g.mu.Lock()
	for ip, e := range g.entries {
		if e.fails == 0 && !now.Before(e.banUntil) {
			delete(g.entries, ip)
		}
	}
	g.mu.Unlock()
}
