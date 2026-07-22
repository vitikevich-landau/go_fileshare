package config

import (
	"testing"
	"time"
)

// TestApplyWithLinearizesEffect covers R3-4: ApplyWith runs its runtime-effect
// callback under the same writer lock as the snapshot swap, so a concurrent Set
// cannot interleave between the swap and its effect and leave them diverged.
// Here the effect blocks; a Set started while it blocks must not run its own
// onChange until the effect (and thus the lock) is released.
func TestApplyWithLinearizesEffect(t *testing.T) {
	h := NewHub(Default())

	order := make(chan string, 4)
	h.SetOnChange(func(k, v string) { order <- "set-effect" })

	started := make(chan struct{})
	release := make(chan struct{})
	applyReturned := make(chan struct{})
	go func() {
		next := Default()
		next.Server.Motd = "applied"
		_ = h.ApplyWith(next, func(s *Settings) {
			// The snapshot must already be swapped in when the effect runs.
			if h.Current().Server.Motd != "applied" {
				t.Errorf("effect ran before the snapshot swap")
			}
			order <- "apply-effect"
			close(started)
			<-release
		})
		close(applyReturned)
	}()

	<-started
	setReturned := make(chan struct{})
	go func() {
		_ = h.Set("server.motd", "viaset")
		close(setReturned)
	}()

	// While ApplyWith holds the lock inside its effect, the Set must block.
	select {
	case <-setReturned:
		t.Fatal("Set completed while ApplyWith still held the writer lock (R3-4)")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-applyReturned
	<-setReturned

	// The apply effect must have run strictly before the set effect.
	if got := <-order; got != "apply-effect" {
		t.Fatalf("first effect = %q, want apply-effect", got)
	}
	if got := <-order; got != "set-effect" {
		t.Fatalf("second effect = %q, want set-effect", got)
	}
}
