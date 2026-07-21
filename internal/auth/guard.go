package auth

import (
	"sync"
	"time"
)

// Guard throttles password guessing by banning an IP after too many
// consecutive authentication failures (docs/tz/09-go-port.md §5.3). Time is
// passed in so behaviour is deterministic in tests.
type Guard struct {
	maxFails int

	mu      sync.Mutex
	entries map[string]*guardEntry
}

type guardEntry struct {
	fails    int
	banUntil time.Time
}

// NewGuard returns a Guard that bans after maxFails consecutive failures.
func NewGuard(maxFails int) *Guard {
	if maxFails < 1 {
		maxFails = 3
	}
	return &Guard{maxFails: maxFails, entries: map[string]*guardEntry{}}
}

// Banned reports whether ip is currently banned as of now.
func (g *Guard) Banned(ip string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[ip]
	return e != nil && now.Before(e.banUntil)
}

// Fail records a failed attempt from ip. When the failure count reaches
// maxFails the ip is banned for banDur (and the counter resets). It returns
// whether the ip is now banned.
func (g *Guard) Fail(ip string, now time.Time, banDur time.Duration) bool {
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

// Success clears any recorded failures for ip.
func (g *Guard) Success(ip string) {
	g.mu.Lock()
	delete(g.entries, ip)
	g.mu.Unlock()
}

// Cleanup drops entries whose ban has expired and that have no pending
// failures, bounding memory for a churning set of client IPs.
func (g *Guard) Cleanup(now time.Time) {
	g.mu.Lock()
	for ip, e := range g.entries {
		if e.fails == 0 && !now.Before(e.banUntil) {
			delete(g.entries, ip)
		}
	}
	g.mu.Unlock()
}
