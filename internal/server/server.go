// Package server реализует демон fileshare v2: цикл приёма соединений,
// рукопожатие и цикл запросов на каждое соединение, реестр сессий, обработчики
// файловой системы и передач, корректную остановку (docs/tz/09-go-port.md §5.5).
//
// Модель конкурентности (горутина-писатель / читатель / сторож простоя /
// горутина закачки) и словарь типов описаны в types.go.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/ratelimit"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// Options — параметры конструктора Server (зависимости и настройки, которые
// сервер не создаёт сам, а получает снаружи).
type Options struct {
	Hub        *config.Hub  // хаб горячих настроек (снапшоты)
	VFS        *vfs.VFS     // дерево раздачи + checksum-кэш
	Users      *auth.DB     // база пользователей (nil/пусто = bootstrap без входа)
	Guard      *auth.Guard  // анти-brute-force бан по IP
	Logger     *slog.Logger // структурный логгер
	ServerName string       // самоназвание в HELLO_OK
	Version    string       // версия для ADMIN_STATS
	// ConfigPath, если задан, — куда АТОМАРНО сохранять принятые изменения
	// ADMIN_SET/reload, чтобы они пережили перезапуск.
	ConfigPath string
	// LogLevel, если задан, обновляется на лету при смене log.level, чтобы горячая
	// настройка реально применилась (CR-08). Обработчик логгера нужно строить с
	// этим же LevelVar.
	LogLevel *slog.LevelVar
	// AuthFailDelay — пауза после каждой неудачной аутентификации для замедления
	// перебора (docs/tz/06-security.md §3). Тесты ставят 0.
	AuthFailDelay time.Duration
}

// Server — работающий (или готовый к запуску) демон fileshare. Держит все общие
// службы и счётчики; на каждое соединение заводится своя Session.
type Server struct {
	hub           *config.Hub
	vfs           *vfs.VFS
	users         *auth.DB
	guard         *auth.Guard
	log           *slog.Logger
	name          string
	version       string
	start         time.Time
	authFailDelay time.Duration
	configPath    string
	logLevelVar   *slog.LevelVar
	limiter       *ratelimit.Limiter

	reg *Registry    // реестр живых сессий
	ln  net.Listener // TCP-слушатель

	serveCancel context.CancelFunc // отменяет цикл приёма (ADMIN_SHUTDOWN)
	adminGrace  atomic.Int64       // секунды; переопределяет grace при значении > 0

	connWg      sync.WaitGroup // ждёт завершения всех горутин соединений при остановке
	activeConns atomic.Int64   // сейчас открытых соединений (для лимита и статистики)

	// счётчики статистики (все атомарные — читаются админом на лету)
	bytesSent       atomic.Uint64 // всего отдано байт
	completed       atomic.Uint64 // успешно завершённых передач
	activeDownloads atomic.Int64  // идущих закачек
	nextTransfer    atomic.Uint32 // генератор TransferID
	nextSession     atomic.Uint64 // генератор SessionID
}

// New builds a Server from opts.
func New(opts Options) *Server {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	name := opts.ServerName
	if name == "" {
		name = "fshared"
	}
	version := opts.Version
	if version == "" {
		version = "go-2.0"
	}
	s := &Server{
		hub:           opts.Hub,
		vfs:           opts.VFS,
		users:         opts.Users,
		guard:         opts.Guard,
		log:           log,
		name:          name,
		version:       version,
		start:         time.Now(),
		authFailDelay: opts.AuthFailDelay,
		configPath:    opts.ConfigPath,
		logLevelVar:   opts.LogLevel,
		limiter:       ratelimit.New(),
		reg:           NewRegistry(),
	}
	s.adminGrace.Store(-1) // -1 = no admin shutdown requested
	// Persist accepted hot-config changes and notify subscribers.
	opts.Hub.SetOnChange(s.onConfigChange)
	return s
}

// onConfigChange сохраняет текущий снапшот (если задан путь конфига) и рассылает
// EVENT_CONFIG подписанным админам (docs/tz/09-go-port.md §5.4). Вызывается хабом
// после успешного ADMIN_SET.
func (s *Server) onConfigChange(key, value string) {
	// Применяем горячий уровень логирования к живому логгеру (CR-08).
	if key == "log.level" && s.logLevelVar != nil {
		s.logLevelVar.Set(parseLogLevel(value))
	}
	if s.configPath != "" {
		if err := s.hub.Current().Save(s.configPath); err != nil {
			s.log.Error("failed to persist config change", "key", key, "err", err)
		}
	}
	frame := proto.Encode(proto.EventConfig{Key: key, NewValue: value})
	s.reg.broadcast(proto.SubConfig, frame)
}

// parseLogLevel maps a config level string to slog.Level (defaults to info).
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Registry exposes the session registry (used by the watcher/admin layers).
func (s *Server) Registry() *Registry { return s.reg }

// authMode — NONE, когда пользователей нет (bootstrap: любой логин = admin),
// иначе CHALLENGE.
func (s *Server) authMode() proto.AuthMode {
	if s.users == nil || s.users.Empty() {
		return proto.AuthNone
	}
	return proto.AuthChallenge
}

// Listen binds the TCP listener. Call before Serve. Addr reports the bound
// address (useful with ":0" in tests).
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Addr returns the bound listen address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve крутит цикл приёма соединений до отмены ctx, затем «сливает» активные
// соединения в течение не более grace, прежде чем принудительно их закрыть.
// Каждое принятое соединение обрабатывается в своей горутине (handleConn), а
// лимит MaxConnections проверяется на входе.
func (s *Server) Serve(ctx context.Context, grace time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.serveCancel = cancel

	s.startWatcher(ctx)
	s.startRateLimitReaper(ctx)
	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // идёт остановка
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		max := s.hub.Current().Limits.MaxConnections
		if max > 0 && int(s.activeConns.Load()) >= max {
			s.rejectConn(conn)
			continue
		}
		s.activeConns.Add(1)
		s.connWg.Add(1)
		go func(c net.Conn) {
			defer s.connWg.Done()
			defer s.activeConns.Add(-1)
			s.handleConn(c)
		}(conn)
	}
	if g := s.adminGrace.Load(); g >= 0 {
		grace = time.Duration(g) * time.Second
	}
	return s.drain(grace)
}

// Сборщик вёдер rate-limit: удаляет персональные вёдра, простаивавшие дольше
// rateReapTTL, с проверкой каждые rateReapInterval, чтобы карта лимитера
// оставалась ограниченной при меняющемся наборе пользователей (§8 bug 11).
const (
	rateReapInterval = time.Minute
	rateReapTTL      = 10 * time.Minute
)

// startRateLimitReaper launches the idle-bucket reaper, which stops on ctx.
func (s *Server) startRateLimitReaper(ctx context.Context) {
	go s.reapRateBuckets(ctx, rateReapInterval, rateReapTTL)
}

func (s *Server) reapRateBuckets(ctx context.Context, interval, ttl time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.limiter.Cleanup(ttl)
		}
	}
}

// requestShutdown запускает корректную остановку с заданным grace-периодом
// (ADMIN_SHUTDOWN): запоминает grace и отменяет цикл приёма, после чего Serve
// переходит к drain. Рассчитан на однократный вызов.
func (s *Server) requestShutdown(graceSeconds GraceSeconds) {
	s.adminGrace.Store(int64(graceSeconds))
	if s.serveCancel != nil {
		s.serveCancel()
	}
}

func (s *Server) rejectConn(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(proto.Encode(proto.Error{Code: proto.ErrRateLimited, Message: "server at capacity"}))
	conn.Close()
}

// drain ждёт завершения активных соединений не дольше grace, затем принудительно
// закрывает оставшиеся и дожидается выхода их горутин. Так корректная передача
// успевает доиграть, а «зависшие» клиенты не задерживают остановку навсегда.
func (s *Server) drain(grace time.Duration) error {
	done := make(chan struct{})
	go func() {
		s.connWg.Wait()
		close(done)
	}()
	if grace > 0 {
		select {
		case <-done:
		case <-time.After(grace):
			s.log.Info("shutdown grace elapsed, closing connections", "active", s.activeConns.Load())
			s.reg.closeAll()
			<-done
		}
	} else {
		s.reg.closeAll()
		<-done
	}
	return nil
}

// handleConn владеет одним соединением: запускает горутину-писателя, проводит
// рукопожатие и цикл запросов и корректно всё сворачивает на выходе
// (docs/tz/09-go-port.md §5.5).
func (s *Server) handleConn(conn net.Conn) {
	ip := hostOf(conn.RemoteAddr())
	id := s.nextSession.Add(1)

	var cwg sync.WaitGroup
	sess := newSession(id, conn, ip, &cwg)
	s.reg.add(sess)

	cwg.Add(1)
	go func() {
		defer cwg.Done()
		sess.writeLoop()
	}()

	defer func() {
		close(sess.done) // остановить производителей/отправителей; писатель дошлёт очередь

		// Даём писателю ограниченное окно, чтобы дослать оставшиеся кадры
		// (например, финальный AUTH_FAIL/ERROR), прежде чем закрыть силой: вежливый
		// клиент их получит, а переставший читать клиент не сможет затормозить teardown.
		flushed := make(chan struct{})
		go func() { cwg.Wait(); close(flushed) }()
		select {
		case <-flushed:
		case <-time.After(flushTimeout):
			conn.Close()
			<-flushed
		}
		conn.Close()
		s.reg.remove(id)
	}()

	if !s.handshake(sess) {
		return
	}
	s.log.Info("session authenticated", "session", id, "ip", ip, "login", sess.Login(), "role", sess.Role().String())
	s.serveRequests(sess)
}

// hostOf извлекает host (без порта) из сетевого адреса — это и есть ClientIP,
// который сервер пишет в логи и передаёт гарду.
func hostOf(addr net.Addr) ClientIP {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
