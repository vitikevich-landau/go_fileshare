package config

import "strconv"

// KeyInfo — одна строка админского вида конфига: «точечный» ключ, его текущее
// значение строкой и можно ли менять его на лету (docs/tz/05-admin.md §2.3).
// Именно из этих строк админ-панель (F9) рисует таблицу настроек.
type KeyInfo struct {
	Key   ConfigKey   `json:"key"`   // напр. «limits.per_client_bps»
	Value ConfigValue `json:"value"` // текущее значение строкой
	Hot   bool        `json:"hot"`   // true — меняется на лету, false — только рестарт
}

// AdminView возвращает отображаемые настройки в СТАБИЛЬНОМ порядке, помеченные
// как горячие или restart-only, для ADMIN_GET_CONFIG. Стабильный порядок нужен,
// чтобы строки в панели не «прыгали» между запросами.
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
		{"events.debounce_ms", i(s.Events.DebounceMs), false},
		{"auth.pbkdf2_iters", i(s.Auth.PBKDF2Iters), false},
		{"log.level", s.Log.Level, true},
	}
}
