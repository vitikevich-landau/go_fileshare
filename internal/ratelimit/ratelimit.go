// Package ratelimit provides per-client and global token-bucket rate limiting
// for downloads. Limits are read fresh on every chunk, so a live config change
// throttles or unthrottles an already-active transfer (docs/tz/09-go-port.md
// §5.6). Per-client buckets are keyed by login, so N parallel downloads by one
// user share one budget (§8 bug 11).
package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// burstBytes is the bucket depth; it must be >= the largest chunk passed to Wait.
const burstBytes = 1 << 16 // 64 KiB, matches proto.ChunkSize

// Limiter enforces a global bucket plus one bucket per client key.
type Limiter struct {
	mu        sync.Mutex
	global    *rate.Limiter
	globalBps uint64
	clients   map[string]*clientLim
}

type clientLim struct {
	lim      *rate.Limiter
	bps      uint64
	lastUsed time.Time
}

// New returns a limiter that starts unlimited.
func New() *Limiter {
	return &Limiter{
		global:  rate.NewLimiter(rate.Inf, burstBytes),
		clients: map[string]*clientLim{},
	}
}

// Wait blocks until n bytes may be sent for clientKey under the current
// per-client and global limits. A limit of 0 means unlimited. ctx cancels the
// wait (e.g. on cancel or connection teardown).
func (l *Limiter) Wait(ctx context.Context, clientKey string, perClientBps, globalBps uint64, n int) error {
	if g := l.globalLimiter(globalBps); g != nil {
		if err := g.WaitN(ctx, n); err != nil {
			return err
		}
	}
	if c := l.clientLimiter(clientKey, perClientBps); c != nil {
		if err := c.WaitN(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

func (l *Limiter) globalLimiter(bps uint64) *rate.Limiter {
	if bps == 0 {
		return nil // unlimited
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.globalBps != bps {
		l.global.SetLimit(rate.Limit(bps))
		l.globalBps = bps
	}
	return l.global
}

func (l *Limiter) clientLimiter(key string, bps uint64) *rate.Limiter {
	if bps == 0 {
		return nil // unlimited
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
	cl.lastUsed = time.Now()
	return cl.lim
}

// Cleanup drops per-client buckets unused for longer than ttl, bounding memory
// for a churning set of users (§8 bug 11 follow-up).
func (l *Limiter) Cleanup(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	l.mu.Lock()
	for k, cl := range l.clients {
		if cl.lastUsed.Before(cutoff) {
			delete(l.clients, k)
		}
	}
	l.mu.Unlock()
}

// ClientCount returns the number of live per-client buckets. Used by the
// bucket-reaper test and any future metrics.
func (l *Limiter) ClientCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}
