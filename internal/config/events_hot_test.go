package config

import "testing"

// TestHubRejectsEventsAsRestart guards the corrected hot/restart contract: the
// watcher is built once, so events.* cannot be changed at runtime.
func TestHubRejectsEventsAsRestart(t *testing.T) {
	h := NewHub(Default())
	if err := h.Set("events.debounce_ms", "1000"); err == nil {
		t.Fatal("events.debounce_ms must be rejected as restart-only")
	}
	if h.Current().Events.DebounceMs != 500 {
		t.Fatalf("debounce changed despite rejection: %d", h.Current().Events.DebounceMs)
	}

	// The admin view must mark it restart, not hot.
	for _, row := range Default().AdminView() {
		if row.Key == "events.debounce_ms" && row.Hot {
			t.Fatal("events.debounce_ms should be marked restart, not hot")
		}
	}
}
