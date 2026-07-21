// Package server implements the fileshare v2 daemon: accept loop, per-connection
// handshake and request loop, session registry, filesystem/transfer handlers,
// and graceful shutdown (docs/tz/09-go-port.md §5.5).
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
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// Options configures a Server.
type Options struct {
	Hub        *config.Hub
	VFS        *vfs.VFS
	Users      *auth.DB
	Guard      *auth.Guard
	Logger     *slog.Logger
	ServerName string
	Version    string
	// AuthFailDelay is slept after each failed authentication to slow brute
	// force (docs/tz/06-security.md §3). Tests set 0.
	AuthFailDelay time.Duration
}

// Server is a running (or runnable) fileshare daemon.
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

	reg *Registry
	ln  net.Listener

	connWg      sync.WaitGroup
	activeConns atomic.Int64

	// stats
	bytesSent       atomic.Uint64
	completed       atomic.Uint64
	activeDownloads atomic.Int64
	nextTransfer    atomic.Uint32
	nextSession     atomic.Uint64
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
	return &Server{
		hub:           opts.Hub,
		vfs:           opts.VFS,
		users:         opts.Users,
		guard:         opts.Guard,
		log:           log,
		name:          name,
		version:       version,
		start:         time.Now(),
		authFailDelay: opts.AuthFailDelay,
		reg:           NewRegistry(),
	}
}

// Registry exposes the session registry (used by the watcher/admin layers).
func (s *Server) Registry() *Registry { return s.reg }

// authMode is NONE when there are no users (bootstrap), else CHALLENGE.
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

// Serve runs the accept loop until ctx is cancelled, then drains active
// connections for up to grace before force-closing them.
func (s *Server) Serve(ctx context.Context, grace time.Duration) error {
	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // shutting down
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
	return s.drain(grace)
}

func (s *Server) rejectConn(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(proto.Encode(proto.Error{Code: proto.ErrRateLimited, Message: "server at capacity"}))
	conn.Close()
}

// drain waits for active connections to finish, up to grace, then force-closes
// any that remain and waits for their goroutines to exit.
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

// handleConn owns one connection: it starts the writer goroutine, runs the
// handshake and request loop, and tears everything down on exit (docs/tz/09-go-port.md §5.5).
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
		close(sess.done) // stop producers/senders; writer flushes queued frames

		// Give the writer a bounded window to flush remaining frames (e.g. a
		// final AUTH_FAIL/ERROR) before force-closing, so a well-behaved client
		// receives them; a client that stops reading cannot stall teardown.
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

func hostOf(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
