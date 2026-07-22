// Package ratelimit ограничивает скорость скачивания по схеме token bucket на
// двух уровнях: глобальном и на клиента. Лимиты читаются заново на каждом чанке,
// поэтому живое изменение конфига тормозит или ускоряет уже идущую передачу
// (docs/tz/09-go-port.md §5.6). Персональные вёдра ключуются по ЛОГИНУ, так что N
// параллельных закачек одного пользователя делят один бюджет (§8 bug 11).
//
// Смысл token bucket и словарь типов — в types.go.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// burstBytes — глубина ведра; она должна быть >= самого большого чанка, который
// передают в Wait (иначе один чанк никогда не поместится и Wait зависнет).
const burstBytes = 1 << 16 // 64 КиБ, совпадает с proto.ChunkSize

// Limiter применяет глобальное ведро плюс по одному ведру на ключ клиента.
type Limiter struct {
	mu        sync.Mutex            // защищает поля ниже
	global    *rate.Limiter         // глобальное ведро (одно на весь сервер)
	globalBps BytesPerSecond        // текущий глобальный лимит (для отслеживания смены)
	clients   map[string]*clientLim // ключ ClientKey → персональное ведро
}

// clientLim — персональное ведро одного клиента плюс учёт «занятости», чтобы
// сборщик (Cleanup) не удалил ведро прямо во время ожидания в нём.
type clientLim struct {
	lim      *rate.Limiter  // само ведро
	bps      BytesPerSecond // лимит, на который оно настроено (для отслеживания смены)
	lastUsed time.Time      // когда им пользовались в последний раз (для Cleanup)
	active   int            // сколько WaitN сейчас «в полёте»; ведро с active > 0 не удаляют
}

// New возвращает лимитер, который стартует БЕЗ ограничений (rate.Inf).
func New() *Limiter {
	return &Limiter{
		global:  rate.NewLimiter(rate.Inf, burstBytes),
		clients: map[string]*clientLim{},
	}
}

// Wait блокируется, пока для clientKey можно будет отдать n байт при текущих
// персональном и глобальном лимитах. Лимит 0 означает «без ограничения». ctx
// отменяет ожидание (например, при отмене передачи или разрыве соединения).
// Порядок важен: сначала ждём глобальное ведро, затем персональное.
func (l *Limiter) Wait(ctx context.Context, clientKey ClientKey, perClientBps, globalBps BytesPerSecond, n ByteCount) error {
	if g := l.globalLimiter(globalBps); g != nil {
		if err := g.WaitN(ctx, n); err != nil {
			return err
		}
	}
	cl := l.acquireClient(clientKey, perClientBps)
	if cl == nil {
		return nil // персональный лимит не задан
	}
	defer l.releaseClient(clientKey)
	return cl.lim.WaitN(ctx, n)
}

// globalLimiter возвращает глобальное ведро, подстроив его под текущий лимит bps
// (перенастройка на лету), либо nil если лимита нет.
func (l *Limiter) globalLimiter(bps BytesPerSecond) *rate.Limiter {
	if bps == 0 {
		return nil // без ограничения
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.globalBps != bps {
		l.global.SetLimit(rate.Limit(bps))
		l.globalBps = bps
	}
	return l.global
}

// acquireClient возвращает персональное ведро (создавая или перенастраивая его) и
// помечает одну «занятость», чтобы сборщик не удалил ведро в середине ожидания.
// На каждый ненулевой возврат вызывающий ОБЯЗАН вызвать releaseClient.
func (l *Limiter) acquireClient(key ClientKey, bps BytesPerSecond) *clientLim {
	if bps == 0 {
		return nil // без ограничения
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cl := l.clients[key]
	if cl == nil {
		cl = &clientLim{lim: rate.NewLimiter(rate.Limit(bps), burstBytes), bps: bps}
		l.clients[key] = cl
	} else if cl.bps != bps {
		cl.lim.SetLimit(rate.Limit(bps))
		cl.bps = bps
	}
	cl.active++
	cl.lastUsed = time.Now()
	return cl
}

// releaseClient снимает одну «занятость» и обновляет lastUsed, чтобы ведро,
// долго простоявшее в WaitN, датировалось моментом окончания ожидания, а не начала.
func (l *Limiter) releaseClient(key ClientKey) {
	l.mu.Lock()
	if cl := l.clients[key]; cl != nil {
		if cl.active > 0 {
			cl.active--
		}
		cl.lastUsed = time.Now()
	}
	l.mu.Unlock()
}

// Cleanup удаляет персональные вёдра, не использовавшиеся дольше ttl, ограничивая
// память при постоянно меняющемся наборе пользователей (§8 bug 11, продолжение).
// Ведро с active > 0 (в нём кто-то сейчас ждёт) не удаляется.
func (l *Limiter) Cleanup(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	l.mu.Lock()
	for k, cl := range l.clients {
		if cl.active == 0 && cl.lastUsed.Before(cutoff) {
			delete(l.clients, k)
		}
	}
	l.mu.Unlock()
}

// ClientCount возвращает число живых персональных вёдер. Используется тестом
// сборщика вёдер и любыми будущими метриками.
func (l *Limiter) ClientCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}
