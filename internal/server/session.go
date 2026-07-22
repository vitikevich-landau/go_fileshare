package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// writeDeadline bounds a single socket write so a stuck client cannot wedge the
// writer goroutine forever.
const writeDeadline = 30 * time.Second

// flushTimeout bounds how long teardown waits for the writer to flush queued
// frames before force-closing the socket.
const flushTimeout = 2 * time.Second

// idlePollCap bounds how long the request loop blocks on a single read before
// re-checking idle/transfer state, so an active download is never mistaken for
// an idle connection (CR-03).
const idlePollCap = 15 * time.Second

// outBuffer is the per-session outgoing queue depth.
const outBuffer = 64

var emptyPath = ""

// Session is one connected client. Outgoing frames go through the out channel,
// drained by a single writer goroutine, so writes are serialized (frames are
// atomic on the wire) and a slow client backpressures only its own transfers —
// broadcasts use a non-blocking send and are dropped rather than blocking others
// (docs/tz/09-go-port.md §5.5).
type Session struct {
	ID   uint64
	IP   string
	conn net.Conn

	out  chan []byte
	done chan struct{}
	wg   *sync.WaitGroup // background goroutines (writer + active download)

	challenge []byte // set during handshake

	mu       sync.Mutex
	login    string
	role     proto.Role
	authed   bool
	cancelDL chan struct{} // closes to cancel the active download

	subMask     atomic.Uint32
	bytes       atomic.Uint64
	curPath     atomic.Pointer[string]
	downloading atomic.Bool
	startedAt   time.Time
}

func newSession(id uint64, conn net.Conn, ip string, wg *sync.WaitGroup) *Session {
	s := &Session{
		ID:        id,
		IP:        ip,
		conn:      conn,
		out:       make(chan []byte, outBuffer),
		done:      make(chan struct{}),
		wg:        wg,
		startedAt: time.Now(),
	}
	s.curPath.Store(&emptyPath)
	return s
}

// send queues a frame, blocking for backpressure until it is accepted or the
// session is being torn down.
func (s *Session) send(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	case <-s.done:
		return false
	}
}

// trySend queues a frame without blocking, dropping it if the queue is full.
// Used for broadcasts so one slow client cannot stall delivery to others.
func (s *Session) trySend(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	default:
		return false
	}
}

func (s *Session) sendMsg(m proto.Message) bool    { return s.send(proto.Encode(m)) }
func (s *Session) trySendMsg(m proto.Message) bool { return s.trySend(proto.Encode(m)) }

// writeLoop drains out to the socket until the session is torn down, then makes
// a best-effort flush of anything still queued.
func (s *Session) writeLoop() {
	for {
		select {
		case frame := <-s.out:
			if !s.writeFrame(frame) {
				return
			}
		case <-s.done:
			for {
				select {
				case frame := <-s.out:
					if !s.writeFrame(frame) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *Session) writeFrame(frame []byte) bool {
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if _, err := s.conn.Write(frame); err != nil {
		s.conn.Close() // unblock the reader on a dead socket
		return false
	}
	return true
}

func (s *Session) setAuthed(login string, role proto.Role) {
	s.mu.Lock()
	s.login = login
	s.role = role
	s.authed = true
	s.mu.Unlock()
}

func (s *Session) Login() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login
}

func (s *Session) Role() proto.Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.role
}

func (s *Session) Authed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authed
}

// setCancel installs the cancel channel for the active download.
func (s *Session) setCancel(c chan struct{}) {
	s.mu.Lock()
	s.cancelDL = c
	s.mu.Unlock()
}

// cancelDownload closes the active download's cancel channel, if any.
func (s *Session) cancelDownload() {
	s.mu.Lock()
	c := s.cancelDL
	s.cancelDL = nil
	s.mu.Unlock()
	if c != nil {
		close(c)
	}
}

func (s *Session) setCurPath(p string) { s.curPath.Store(&p) }
func (s *Session) clearCurPath()       { s.curPath.Store(&emptyPath) }
func (s *Session) CurPath() string {
	if p := s.curPath.Load(); p != nil {
		return *p
	}
	return ""
}

// Registry tracks live sessions.
type Registry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
}

func NewRegistry() *Registry { return &Registry{sessions: map[uint64]*Session{}} }

func (r *Registry) add(s *Session) {
	r.mu.Lock()
	r.sessions[s.ID] = s
	r.mu.Unlock()
}

func (r *Registry) remove(id uint64) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

func (r *Registry) get(id uint64) (*Session, bool) {
	r.mu.Lock()
	s, ok := r.sessions[id]
	r.mu.Unlock()
	return s, ok
}

func (r *Registry) list() []*Session {
	r.mu.Lock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.mu.Unlock()
	return out
}

func (r *Registry) count() int {
	r.mu.Lock()
	n := len(r.sessions)
	r.mu.Unlock()
	return n
}

// reserveUserSlot atomically enforces the per-user session cap and, if there is
// room, marks sess authenticated — so concurrent handshakes for one user cannot
// all slip past the check before any of them commits (CR-06). max <= 0 means no
// limit. It returns whether the slot was granted.
func (r *Registry) reserveUserSlot(sess *Session, login string, role proto.Role, max int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max > 0 {
		n := 0
		for _, s := range r.sessions {
			if s != sess && s.Authed() && s.Login() == login {
				n++
			}
		}
		if n >= max {
			return false
		}
	}
	sess.setAuthed(login, role)
	return true
}

// closeAll force-closes every session's socket (used on shutdown after grace).
func (r *Registry) closeAll() {
	for _, s := range r.list() {
		s.conn.Close()
	}
}

// broadcast queues frame to every session subscribed to any bit in mask, using
// a non-blocking send (docs/tz/09-go-port.md §5.5).
func (r *Registry) broadcast(mask uint32, frame []byte) {
	for _, s := range r.list() {
		if s.subMask.Load()&mask != 0 {
			s.trySend(frame)
		}
	}
}
