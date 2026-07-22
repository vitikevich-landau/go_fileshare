package config

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
)

// Hub хранит живой снапшот настроек. Читатели берут Current() — ОДНА атомарная
// загрузка, никогда не блокирует — на горячем пути (на каждый чанк, на каждый
// accept). Писатели сериализуются под wmu, строят новый снапшот, валидируют и
// атомарно ПОДМЕНЯЮТ указатель (docs/tz/09-go-port.md §5.4).
type Hub struct {
	snap     atomic.Pointer[Settings] // текущий снапшот (подменяется целиком)
	wmu      sync.Mutex               // сериализует писателей (не читателей!)
	onChange func(key, value string)  // колбэк после успешного Set
}

// NewHub возвращает Hub, инициализированный снапшотом s.
func NewHub(s Settings) *Hub {
	h := &Hub{}
	h.snap.Store(&s)
	return h
}

// Current возвращает активный снапшот. Его нужно считать ТОЛЬКО ДЛЯ ЧТЕНИЯ:
// писатели никогда не меняют опубликованный снапшот на месте, а публикуют новый.
func (h *Hub) Current() *Settings { return h.snap.Load() }

// SetOnChange регистрирует колбэк, вызываемый после успешного Set с ключом и
// новым значением. Сервер использует его, чтобы сохранить конфиг на диск и
// разослать EVENT_CONFIG подписчикам.
func (h *Hub) SetOnChange(fn func(key ConfigKey, value ConfigValue)) { h.onChange = fn }

// Apply валидирует и подменяет ЦЕЛИКОМ новый снапшот (используется при SIGHUP
// reload). Работает под писательским локом, поэтому не гоняется с Set.
func (h *Hub) Apply(next Settings) error { return h.ApplyWith(next, nil) }

// ApplyWith — это Apply, который вдобавок выполняет effect над новым снапшотом,
// ещё удерживая писательский лок. Это ЛИНЕАРИЗУЕТ полную подмену снапшота с её
// побочным эффектом (например, живым уровнем логирования): параллельный Set не
// сможет вклиниться между публикацией снапшота и его эффектом и оставить их
// рассогласованными (R3-4).
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

// restartKeys — ключи, которые нельзя менять на лету, только перезапуском
// (docs/tz/09-go-port.md §12.1). Set отвергает их с понятной ошибкой, а не молча
// принимает изменение, которое ни на что не повлияет.
var restartKeys = map[string]bool{
	"server.port":         true,
	"server.share_root":   true,
	"server.workers":      true,
	"checksum.cache_file": true,
	"auth.pbkdf2_iters":   true,
	"auth.users_file":     true,
	// Watcher строится один раз при старте и никогда не перечитывает свой
	// debounce, поэтому считаем эти ключи restart-only, а не молча принимаем
	// изменение без эффекта.
	"events.debounce_ms": true,
	"events.enabled":     true,
}

// Set меняет один горячий ключ на value, валидирует получившийся снапшот и
// атомарно подменяет его. Restart-only и неизвестные ключи отвергаются. При успехе
// колбэк onChange (если задан) вызывается ПОД писательским локом, чтобы записанный
// на диск файл и рассылка отражали один и тот же снапшот.
func (h *Hub) Set(key ConfigKey, value ConfigValue) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()

	next := *h.Current() // копируем текущий снапшот
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

// applyKey разбирает value и присваивает его горячему ключу в s. Числовые значения
// парсятся в широкий тип и проверяются на диапазон ДО присваивания, чтобы слишком
// большое значение было отвергнуто, а не молча «завернулось» переполнением
// (docs/tz/09-go-port.md §8, bug 13).
func applyKey(s *Settings, key ConfigKey, value ConfigValue) error {
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
