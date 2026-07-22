package server

import (
	"context"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/ratelimit"
)

// The idle per-client rate buckets must be reaped so the limiter map stays
// bounded for a churning user set (§8 bug 11 follow-up). This exercises the
// reaper loop wired into Serve with a fast interval and tiny TTL.
func TestReapRateBucketsDropsIdle(t *testing.T) {
	s := &Server{limiter: ratelimit.New()}

	// Seed one per-client bucket (a non-zero per-client limit creates it).
	if err := s.limiter.Wait(context.Background(), "alice", 1<<20, 0, 1); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}
	if got := s.limiter.ClientCount(); got != 1 {
		t.Fatalf("ClientCount after seed = %d, want 1", got)
	}

	// Let the bucket age past the (tiny) TTL, then run the reaper fast.
	time.Sleep(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.reapRateBuckets(ctx, 5*time.Millisecond, time.Millisecond)

	deadline := time.After(2 * time.Second)
	for s.limiter.ClientCount() != 0 {
		select {
		case <-deadline:
			t.Fatal("idle per-client bucket was not reaped")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
