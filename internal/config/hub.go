package config

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
)

// Hub holds the live settings snapshot. Readers take Current() — a single
// atomic load, never blocking — on the hot path (per chunk, per accept). Writers
// serialize under wmu, build a new snapshot, validate, then swap it in
// (docs/tz/09-go-port.md §5.4).
type Hub struct {
	snap     atomic.Pointer[Settings]
	wmu      sync.Mutex
	onChange func(key, value string)
}

// NewHub returns a Hub seeded with s.
func NewHub(s Settings) *Hub {
	h := &Hub{}
	h.snap.Store(&s)
	return h
}

// Current returns the active snapshot. The returned value must be treated as
// read-only; writers never mutate a published snapshot in place.
func (h *Hub) Current() *Settings { return h.snap.Load() }

// SetOnChange registers a callback invoked after a successful Set, with the key
// and new value. The server uses it to persist config and broadcast EVENT_CONFIG.
func (h *Hub) SetOnChange(fn func(key, value string)) { h.onChange = fn }

// Apply validates and swaps in an entirely new snapshot (used by SIGHUP reload).
// It runs under the writer lock so it cannot race with Set.
func (h *Hub) Apply(next Settings) error { return h.ApplyWith(next, nil) }

// ApplyWith is Apply that also runs effect against the new snapshot while still
// holding the writer lock. This linearizes a full snapshot swap with its runtime
// side effect (e.g. the live log level), so a concurrent Set can never publish a
// snapshot and its effect in between the two and leave them diverged (R3-4).
func (h *Hub) ApplyWith(next Settings, effect func(*Settings)) error {
	if msg := next.Validate(); msg != "" {
		return fmt.Errorf("config: %s", msg)
	}
	h.wmu.Lock()
	defer h.wmu.Unlock()
	h.snap.Store(&next)
	if effect != nil {
		effect(&next)
	}
	return nil
}

// restartKeys cannot be changed at runtime, only by restart (docs/tz/09-go-port.md §12.1).
var restartKeys = map[string]bool{
	"server.port":         true,
	"server.share_root":   true,
	"server.workers":      true,
	"checksum.cache_file": true,
	"auth.pbkdf2_iters":   true,
	"auth.users_file":     true,
	// The watcher is constructed once at startup and never re-reads its
	// debounce, so treat it as restart-only rather than silently accepting a
	// change that has no runtime effect.
	"events.debounce_ms": true,
	"events.enabled":     true,
}

// Set changes one hot key to value, validates the resulting snapshot, and swaps
// it in atomically. Restart-only and unknown keys are rejected. On success the
// onChange callback (if any) is invoked while holding the writer lock, so the
// persisted file and any broadcast reflect the same snapshot.
func (h *Hub) Set(key, value string) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()

	next := *h.Current() // copy the current snapshot
	if err := applyKey(&next, key, value); err != nil {
		return err
	}
	if msg := next.Validate(); msg != "" {
		return fmt.Errorf("value rejected: %s", msg)
	}
	h.snap.Store(&next)
	if h.onChange != nil {
		h.onChange(key, value)
	}
	return nil
}

// applyKey parses value and assigns it to the hot key on s. Numeric values are
// parsed into a wide type and range-checked before assignment, so an oversized
// value is rejected rather than silently wrapped (docs/tz/09-go-port.md §8, bug 13).
func applyKey(s *Settings, key, value string) error {
	nonNegInt := func() (int, error) {
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("key %q: %q is not an integer", key, value)
		}
		if v < 0 {
			return 0, fmt.Errorf("key %q: must be >= 0", key)
		}
		if v > int64(maxInt) {
			return 0, fmt.Errorf("key %q: %d too large", key, v)
		}
		return int(v), nil
	}
	u64 := func() (uint64, error) {
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("key %q: %q is not an unsigned integer", key, value)
		}
		return v, nil
	}

	switch key {
	case "limits.per_client_bps":
		v, err := u64()
		if err != nil {
			return err
		}
		s.Limits.PerClientBps = v
	case "limits.global_bps":
		v, err := u64()
		if err != nil {
			return err
		}
		s.Limits.GlobalBps = v
	case "limits.max_connections":
		v, err := nonNegInt()
		if err != nil {
			return err
		}
		s.Limits.MaxConnections = v
	case "limits.max_sessions_per_user":
		v, err := nonNegInt()
		if err != nil {
			return err
		}
		s.Limits.MaxSessionsPerUser = v
	case "limits.handshake_timeout_s":
		v, err := nonNegInt()
		if err != nil {
			return err
		}
		s.Limits.HandshakeTimeoutS = v
	case "limits.idle_timeout_s":
		v, err := nonNegInt()
		if err != nil {
			return err
		}
		s.Limits.IdleTimeoutS = v
	case "limits.auth_fail_ban_s":
		v, err := nonNegInt()
		if err != nil {
			return err
		}
		s.Limits.AuthFailBanS = v
	case "server.motd":
		s.Server.Motd = value
	case "log.level":
		s.Log.Level = value
	default:
		if restartKeys[key] {
			return fmt.Errorf("key %q requires a restart and cannot be set at runtime", key)
		}
		return fmt.Errorf("unknown or non-hot key %q", key)
	}
	return nil
}

const maxInt = int64(^uint(0) >> 1)
