package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestUnlimitedDoesNotBlock(t *testing.T) {
	l := New()
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 200; i++ {
		if err := l.Wait(ctx, "vit", 0, 0, 65536); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Fatalf("unlimited waits took %v, expected ~0", el)
	}
}

func TestPerClientThrottles(t *testing.T) {
	l := New()
	ctx := context.Background()
	const bps = 200000 // 200 KB/s
	const want = 300000
	start := time.Now()
	sent := 0
	for sent < want {
		n := 65536
		if want-sent < n {
			n = want - sent
		}
		if err := l.Wait(ctx, "vit", bps, 0, n); err != nil {
			t.Fatal(err)
		}
		sent += n
	}
	el := time.Since(start)
	// The first burst is free; the remaining ~234 KB at 200 KB/s is >~1.1s.
	if el < 800*time.Millisecond {
		t.Fatalf("throttle too fast: %v", el)
	}
}

func TestCancelUnblocksWait(t *testing.T) {
	l := New()
	ctx, cancel := context.WithCancel(context.Background())
	// Drain the initial burst so the next Wait must block.
	_ = l.Wait(ctx, "vit", 1000, 0, 65536)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := l.Wait(ctx, "vit", 1000, 0, 65536) // would take ~65s unthrottled by cancel
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("cancel did not unblock promptly: %v", el)
	}
}
