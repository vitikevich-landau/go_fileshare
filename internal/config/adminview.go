package config

import "strconv"

// KeyInfo is one row of the admin config view: a dotted key, its current value
// as a string, and whether it can be changed at runtime (docs/tz/05-admin.md §2.3).
type KeyInfo struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Hot   bool   `json:"hot"`
}

// AdminView returns the displayable settings in a stable order, marked hot or
// restart-only, for ADMIN_GET_CONFIG.
func (s Settings) AdminView() []KeyInfo {
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	i := func(v int) string { return strconv.Itoa(v) }
	return []KeyInfo{
		{"server.port", i(s.Server.Port), false},
		{"server.share_root", s.Server.ShareRoot, false},
		{"server.motd", s.Server.Motd, true},
		{"limits.max_connections", i(s.Limits.MaxConnections), true},
		{"limits.max_sessions_per_user", i(s.Limits.MaxSessionsPerUser), true},
		{"limits.per_client_bps", u(s.Limits.PerClientBps), true},
		{"limits.global_bps", u(s.Limits.GlobalBps), true},
		{"limits.handshake_timeout_s", i(s.Limits.HandshakeTimeoutS), true},
		{"limits.idle_timeout_s", i(s.Limits.IdleTimeoutS), true},
		{"limits.auth_fail_ban_s", i(s.Limits.AuthFailBanS), true},
		{"events.debounce_ms", i(s.Events.DebounceMs), true},
		{"auth.pbkdf2_iters", i(s.Auth.PBKDF2Iters), false},
		{"log.level", s.Log.Level, true},
	}
}
