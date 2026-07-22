// Package config хранит настройки демона и хаб горячей перезагрузки.
//
// Settings — плоская value-структура (без указателей/срезов/карт), поэтому её
// снимок (snapshot) — дешёвая копия по значению. Это основа lock-free горячего
// конфига через Hub (docs/tz/09-go-port.md §5.4, §12.1). Механизм снапшотов и
// деление настроек на «горячие» и «рестарт-» подробно описаны в types.go.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ServerSettings — «кто и откуда» раздаётся. Почти всё здесь restart-only.
type ServerSettings struct {
	Port      Port   `json:"port"`       // restart: TCP-порт демона
	ShareRoot string `json:"share_root"` // restart: корневая директория раздачи
	Workers   int    `json:"workers"`    // restart: число воркеров; 0 = по числу CPU
	Motd      string `json:"motd"`       // hot: приветствие в AUTH_OK
}

// LimitsSettings — лимиты и тайм-ауты. Все — «горячие»: меняются на лету.
type LimitsSettings struct {
	MaxConnections     int            `json:"max_connections"`       // hot; 0 = без лимита
	MaxSessionsPerUser int            `json:"max_sessions_per_user"` // hot; 0 = без лимита
	PerClientBps       BytesPerSecond `json:"per_client_bps"`        // hot; 0 = без лимита
	GlobalBps          BytesPerSecond `json:"global_bps"`            // hot; 0 = без лимита
	HandshakeTimeoutS  Seconds        `json:"handshake_timeout_s"`   // hot: тайм-аут рукопожатия
	IdleTimeoutS       Seconds        `json:"idle_timeout_s"`        // hot: тайм-аут простоя
	AuthFailBanS       Seconds        `json:"auth_fail_ban_s"`       // hot: срок бана за брутфорс
}

// ChecksumSettings — где лежит checksum-кэш VFS.
type ChecksumSettings struct {
	CacheFile string `json:"cache_file"` // restart: файл checksum-кэша
}

// EventsSettings — параметры watcher-а (push-события EVENT_FS). Строятся один раз
// при старте, поэтому restart-only.
type EventsSettings struct {
	Enabled    bool         `json:"enabled"`     // restart: включён ли watcher
	DebounceMs Milliseconds `json:"debounce_ms"` // restart: пауза «схлопывания» событий
}

// AuthSettings — путь к users.json и число итераций PBKDF2. Сам ФАЙЛ читается
// горячо (Reload), а вот путь и число итераций — restart.
type AuthSettings struct {
	UsersFile   string `json:"users_file"`   // restart (путь); содержимое — горячее
	PBKDF2Iters int    `json:"pbkdf2_iters"` // restart: итераций PBKDF2
}

// LogSettings — уровень логирования (меняется на лету).
type LogSettings struct {
	Level string `json:"level"` // hot: debug|info|warn|error
}

// Settings — полная конфигурация демона: дерево из подгрупп выше.
type Settings struct {
	Server   ServerSettings   `json:"server"`
	Limits   LimitsSettings   `json:"limits"`
	Checksum ChecksumSettings `json:"checksum"`
	Events   EventsSettings   `json:"events"`
	Auth     AuthSettings     `json:"auth"`
	Log      LogSettings      `json:"log"`
}

// MinPBKDF2Iters — рекомендуемое число итераций PBKDF2 (порог безопасности из
// docs/tz/06-security.md §2). Это СОВЕТ, не жёсткое требование при загрузке:
// демон объявляет это значение в HELLO_OK *до* того, как узнает логин
// (challenge/response), значит оно едино для всей установки — поднять его значит
// обесценить все существующие хеши. Отвергать конфиг ниже порога при загрузке
// заодно заблокировало бы --reset-password (тот самый инструмент миграции).
// Поэтому демон лишь предупреждает при старте, оставляя старые установки
// работоспособными на время миграции. Пофайловое число итераций требует
// отложенного изменения рукопожатия (B1-full).
const MinPBKDF2Iters = 600_000

// Default возвращает встроенные значения по умолчанию (docs/tz/09-go-port.md §12.1).
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

// Clone возвращает глубокую копию. Благодаря value-семантике Settings это
// обычное копирование по значению — именно поэтому снапшоты так дёшевы.
func (s Settings) Clone() Settings { return s }

// Load читает конфиг из path, НАКЛАДЫВАЯ его поверх значений по умолчанию: частичный
// файл переопределяет только заданные в нём ключи. Отсутствующий файл даёт
// умолчания и не считается ошибкой. Результат валидируется.
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

// Validate возвращает человекочитаемую причину, по которой настройки некорректны,
// или "" если они валидны (docs/tz/09-go-port.md §12.1). Вызывается и при загрузке
// файла, и перед каждой горячей подменой снапшота — плохое значение не применится.
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

// Save атомарно пишет настройки в path (временный файл + rename), чтобы на диске
// никогда не оказался «полузаписанный» конфиг.
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
