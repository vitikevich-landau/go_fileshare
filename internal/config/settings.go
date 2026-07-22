// Package config holds the daemon settings and the hot-reload hub.
//
// Settings is a plain value struct (no pointers/slices/maps), so a snapshot is
// a cheap by-value copy — the basis for lock-free hot config via Hub
// (docs/tz/09-go-port.md §5.4, §12.1).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type ServerSettings struct {
	Port      int    `json:"port"`       // restart
	ShareRoot string `json:"share_root"` // restart
	Workers   int    `json:"workers"`    // restart; 0 = num CPUs
	Motd      string `json:"motd"`       // hot
}

type LimitsSettings struct {
	MaxConnections     int    `json:"max_connections"`       // hot; 0 = unlimited
	MaxSessionsPerUser int    `json:"max_sessions_per_user"` // hot; 0 = unlimited
	PerClientBps       uint64 `json:"per_client_bps"`        // hot; 0 = unlimited
	GlobalBps          uint64 `json:"global_bps"`            // hot; 0 = unlimited
	HandshakeTimeoutS  int    `json:"handshake_timeout_s"`   // hot
	IdleTimeoutS       int    `json:"idle_timeout_s"`        // hot
	AuthFailBanS       int    `json:"auth_fail_ban_s"`       // hot
}

type ChecksumSettings struct {
	CacheFile string `json:"cache_file"` // restart
}

type EventsSettings struct {
	Enabled    bool `json:"enabled"`     // restart (watcher built once at startup)
	DebounceMs int  `json:"debounce_ms"` // restart (watcher built once at startup)
}

type AuthSettings struct {
	UsersFile   string `json:"users_file"`   // restart (path); contents are hot
	PBKDF2Iters int    `json:"pbkdf2_iters"` // restart
}

type LogSettings struct {
	Level string `json:"level"` // hot
}

// Settings is the full daemon configuration.
type Settings struct {
	Server   ServerSettings   `json:"server"`
	Limits   LimitsSettings   `json:"limits"`
	Checksum ChecksumSettings `json:"checksum"`
	Events   EventsSettings   `json:"events"`
	Auth     AuthSettings     `json:"auth"`
	Log      LogSettings      `json:"log"`
}

// MinPBKDF2Iters is the recommended PBKDF2 iteration count (the security floor
// from docs/tz/06-security.md §2). It is ADVISORY, not enforced at load: because
// the daemon announces this value in HELLO_OK *before* it learns the login
// (challenge/response), it is a deployment-wide constant, so raising it would
// invalidate every existing hash. Rejecting a below-floor config at load would
// also block --reset-password (the very tool used to migrate). The daemon
// therefore warns at startup instead, leaving old installs runnable while they
// migrate. A per-user count needs the deferred B1-full handshake change.
const MinPBKDF2Iters = 600_000

// Default returns the built-in defaults (docs/tz/09-go-port.md §12.1).
func Default() Settings {
	return Settings{
		Server: ServerSettings{Port: 5555, ShareRoot: "./share", Workers: 0, Motd: ""},
		Limits: LimitsSettings{
			MaxConnections: 200, MaxSessionsPerUser: 3,
			PerClientBps: 0, GlobalBps: 0,
			HandshakeTimeoutS: 10, IdleTimeoutS: 600, AuthFailBanS: 60,
		},
		Checksum: ChecksumSettings{CacheFile: "checksums.cache"},
		Events:   EventsSettings{Enabled: true, DebounceMs: 500},
		Auth:     AuthSettings{UsersFile: "users.json", PBKDF2Iters: MinPBKDF2Iters},
		Log:      LogSettings{Level: "info"},
	}
}

// Clone returns a deep copy (value semantics make this a plain copy).
func (s Settings) Clone() Settings { return s }

// Load reads config from path, overlaying it onto the defaults so a partial
// file only overrides the keys it sets. A missing file yields the defaults and
// is not an error. The result is validated.
func Load(path string) (Settings, error) {
	s := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if msg := s.Validate(); msg != "" {
		return s, fmt.Errorf("config: invalid %s: %s", path, msg)
	}
	return s, nil
}

// Validate returns a human-readable reason the settings are invalid, or "" if
// they are valid (docs/tz/09-go-port.md §12.1).
func (s Settings) Validate() string {
	if s.Server.Port < 1 || s.Server.Port > 65535 {
		return fmt.Sprintf("server.port %d out of range [1,65535]", s.Server.Port)
	}
	if s.Server.ShareRoot == "" {
		return "server.share_root must not be empty"
	}
	if s.Limits.GlobalBps > 0 && s.Limits.PerClientBps > s.Limits.GlobalBps {
		return "limits.per_client_bps must be <= limits.global_bps when global_bps > 0"
	}
	if s.Limits.HandshakeTimeoutS <= 0 {
		return "limits.handshake_timeout_s must be > 0"
	}
	if s.Limits.IdleTimeoutS <= 0 {
		return "limits.idle_timeout_s must be > 0"
	}
	if s.Limits.AuthFailBanS <= 0 {
		return "limits.auth_fail_ban_s must be > 0"
	}
	if s.Auth.PBKDF2Iters <= 0 {
		return "auth.pbkdf2_iters must be > 0"
	}
	switch s.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Sprintf("log.level %q must be one of debug|info|warn|error", s.Log.Level)
	}
	return ""
}

// Save atomically writes settings to path (temp + rename).
func (s Settings) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
