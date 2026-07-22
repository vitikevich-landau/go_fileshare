package ratelimit

import (
	"testing"
	"time"
)

// A bucket with an in-flight reservation must survive Cleanup even when it looks
// stale, otherwise a very slow WaitN could be dropped and the next request would
// get a fresh limiter/burst that bypasses the per-client limit.
func TestCleanupSkipsActiveBucket(t *testing.T) {
	l := New()

	cl := l.acquireClient("bob", 1000) // active = 1
	if cl == nil {
		t.Fatal("expected a per-client bucket")
	}

	// Backdate it so it would be reaped if active were ignored.
	l.mu.Lock()
	l.clients["bob"].lastUsed = time.Now().Add(-time.Hour)
	l.mu.Unlock()

	l.Cleanup(time.Minute)
	if l.ClientCount() != 1 {
		t.Fatal("cleanup dropped a bucket with an active reservation")
	}

	// After release, lastUsed is refreshed to now — still not stale.
	l.releaseClient("bob")
	l.Cleanup(time.Minute)
	if l.ClientCount() != 1 {
		t.Fatal("a just-released bucket should not be reaped (fresh lastUsed)")
	}

	// Once genuinely idle, it is reaped.
	l.mu.Lock()
	l.clients["bob"].lastUsed = time.Now().Add(-time.Hour)
	l.mu.Unlock()
	l.Cleanup(time.Minute)
	if l.ClientCount() != 0 {
		t.Fatal("an idle released bucket should be reaped")
	}
}
