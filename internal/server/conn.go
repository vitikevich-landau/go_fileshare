package server

import (
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// handshake runs HELLO -> HELLO_OK -> AUTH_REQUEST -> AUTH_OK|AUTH_FAIL under a
// handshake deadline. It returns true once the session is authenticated
// (docs/tz/09-go-port.md §4.5, §5.5).
func (s *Server) handshake(sess *Session) bool {
	cur := s.hub.Current()
	deadline := time.Now().Add(time.Duration(cur.Limits.HandshakeTimeoutS) * time.Second)
	_ = sess.conn.SetReadDeadline(deadline)

	// Phase 1: wait for HELLO (PING is answered while we wait). Pre-auth frames
	// are read with a small cap so an unauthenticated peer cannot pin memory
	// with an oversized length header (CR-05).
	var hello proto.Hello
	for {
		typ, payload, err := proto.ReadFrameLimited(sess.conn, proto.HandshakeMaxPayload)
		if err != nil {
			// Unparseable first frame (e.g. a v1 client) — best-effort reject.
			sess.trySendMsg(proto.Error{Code: proto.ErrUnsupportedVersion, Message: "expected HELLO"})
			return false
		}
		if typ == proto.MsgPing {
			sess.sendMsg(proto.Pong{})
			continue
		}
		if typ != proto.MsgHello {
			sess.sendMsg(proto.Error{Code: proto.ErrUnsupportedVersion, Message: "expected HELLO"})
			return false
		}
		m, derr := proto.Decode(typ, payload)
		if derr != nil {
			sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "bad HELLO"})
			return false
		}
		hello = m.(proto.Hello)
		break
	}
	if hello.ProtoVer != proto.ProtoVersion {
		sess.sendMsg(proto.Error{Code: proto.ErrUnsupportedVersion, Message: "unsupported protocol version"})
		return false
	}

	// Issue the challenge.
	var challenge [proto.ChallengeLen]byte
	if _, err := crand.Read(challenge[:]); err != nil {
		sess.sendMsg(proto.Error{Code: proto.ErrInternal, Message: "server error"})
		return false
	}
	sess.challenge = challenge[:]
	sess.sendMsg(proto.HelloOk{
		ProtoVer:    proto.ProtoVersion,
		ServerName:  s.name,
		AuthMode:    s.authMode(),
		Challenge:   challenge,
		PBKDF2Iters: uint32(cur.Auth.PBKDF2Iters),
	})

	// Phase 2: wait for AUTH_REQUEST (PING answered while we wait), still under
	// the small pre-auth payload cap (CR-05).
	for {
		typ, payload, err := proto.ReadFrameLimited(sess.conn, proto.HandshakeMaxPayload)
		if err != nil {
			return false
		}
		if typ == proto.MsgPing {
			sess.sendMsg(proto.Pong{})
			continue
		}
		if typ != proto.MsgAuthRequest {
			sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "expected AUTH_REQUEST"})
			return false
		}
		m, derr := proto.Decode(typ, payload)
		if derr != nil {
			sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "bad AUTH_REQUEST"})
			return false
		}
		return s.authenticate(sess, m.(proto.AuthRequest), cur)
	}
}

// authenticate validates the client proof (or accepts any login in no-auth
// bootstrap), enforces the IP ban and per-user session cap, and replies with
// AUTH_OK or AUTH_FAIL. It returns whether authentication succeeded.
func (s *Server) authenticate(sess *Session, req proto.AuthRequest, cur *config.Settings) bool {
	now := time.Now()
	if s.guard.Banned(sess.IP, now) {
		s.log.Warn("authentication rejected: banned", "ip", sess.IP, "login", req.Login)
		sess.sendMsg(proto.AuthFail{Reason: proto.AuthFailBanned, Message: "too many attempts, temporarily banned"})
		return false
	}

	// No-auth bootstrap: any login becomes ADMIN.
	if s.authMode() == proto.AuthNone {
		login := req.Login
		if login == "" {
			login = "admin"
		}
		sess.setAuthed(login, proto.RoleAdmin)
		s.guard.Success(sess.IP)
		sess.sendMsg(proto.AuthOk{Role: proto.RoleAdmin, SessionID: sess.ID, Motd: cur.Server.Motd})
		return true
	}

	storedKey, role, enabled, ok := s.users.Lookup(req.Login)
	valid := ok && enabled && auth.Verify(storedKey, sess.challenge, req.Login, req.Proof)
	if !valid {
		if s.authFailDelay > 0 {
			time.Sleep(s.authFailDelay)
		}
		reason := proto.AuthFailBadCredentials
		reasonText := "bad_credentials"
		if ok && !enabled {
			reason = proto.AuthFailUserDisabled
			reasonText = "user_disabled"
		}
		banned := s.guard.Fail(sess.IP, now, time.Duration(cur.Limits.AuthFailBanS)*time.Second)
		s.log.Warn("authentication failed", "ip", sess.IP, "login", req.Login, "reason", reasonText, "banned", banned)
		msg := "authentication failed"
		if banned {
			msg = "authentication failed; too many attempts, temporarily banned"
		}
		sess.sendMsg(proto.AuthFail{Reason: reason, Message: msg})
		return false
	}

	// Atomically enforce the per-user session cap and mark authenticated, so
	// concurrent logins for one user cannot all pass the check (CR-06).
	if !s.reg.reserveUserSlot(sess, req.Login, role, cur.Limits.MaxSessionsPerUser) {
		s.log.Warn("authentication rejected: too many sessions", "ip", sess.IP, "login", req.Login)
		sess.sendMsg(proto.AuthFail{Reason: proto.AuthFailTooManySession, Message: "too many concurrent sessions"})
		return false
	}
	s.guard.Success(sess.IP)
	sess.sendMsg(proto.AuthOk{Role: role, SessionID: sess.ID, Motd: cur.Server.Motd})
	return true
}

// serveRequests is the post-auth request loop. Reads block without a per-frame
// deadline (so a deadline can never fire mid-frame and desync the stream, RR-1);
// a separate watchdog enforces the idle timeout by closing the connection, which
// unblocks the read for a clean teardown. An active transfer is exempt (CR-03).
func (s *Server) serveRequests(sess *Session) {
	_ = sess.conn.SetReadDeadline(time.Time{}) // clear the handshake deadline
	sess.touch()

	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		s.idleWatchdog(sess)
	}()

	for {
		typ, payload, err := proto.ReadFrame(sess.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTimeout(err) {
				// Framing/protocol error: best-effort notice, then close.
				sess.trySendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "malformed frame"})
			}
			return
		}
		sess.touch()

		if !roleAllows(sess.Role(), MinRole(typ)) {
			s.sendErr(sess, proto.ErrAccessDenied)
			continue
		}

		m, derr := proto.Decode(typ, payload)
		if derr != nil {
			// Malformed payload tears down only this connection.
			sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "malformed payload"})
			return
		}

		// Mark the connection as actively processing for the duration of the
		// handler so a synchronous request that runs longer than idle_timeout_s
		// (a checksum over a big file, a large listing, an admin call) is not
		// reaped as idle mid-flight (R3-6). touch() afterwards gives the response
		// a fresh idle window.
		sess.inFlight.Store(true)
		s.dispatch(sess, m)
		sess.inFlight.Store(false)
		sess.touch()
	}
}

func (s *Server) dispatch(sess *Session, m proto.Message) {
	switch req := m.(type) {
	case proto.Ping:
		sess.sendMsg(proto.Pong{})
	case proto.Subscribe:
		mask := req.Mask
		if sess.Role() != proto.RoleAdmin {
			mask &^= proto.SubConfig // EVENT_CONFIG is admin-only (CR-07)
		}
		sess.subMask.Store(mask)
	case proto.ListDirRequest:
		s.handleList(sess, req)
	case proto.StatRequest:
		s.handleStat(sess, req)
	case proto.ChecksumRequest:
		s.handleChecksum(sess, req)
	case proto.DownloadRequest:
		s.startDownload(sess, req)
	case proto.DownloadCancel:
		sess.cancelDownload(req.TransferID)
	case proto.AdminGetConfig, proto.AdminSet, proto.AdminListClients,
		proto.AdminKick, proto.AdminStats, proto.AdminShutdown, proto.AdminReloadUsers:
		s.handleAdmin(sess, m)
	default:
		// Anything else from a client is a protocol violation.
		sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "unexpected message"})
	}
}

func (s *Server) handleList(sess *Session, req proto.ListDirRequest) {
	clean, entries, err := s.vfs.List(req.Path)
	if err != nil {
		s.sendErr(sess, vfs.CodeOf(err))
		return
	}
	frame, ok := listDirFrame(clean, entries)
	if !ok {
		// A listing that would exceed the frame limit is refused with a
		// controlled error rather than an oversize frame that would break the
		// connection (CR-10). Pagination is a future protocol extension.
		s.log.Warn("directory listing exceeds frame limit", "path", clean, "entries", len(entries))
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	sess.send(frame)
}

// listDirFrame encodes a LIST_DIR_RESPONSE, returning ok=false if its payload
// would exceed the protocol frame limit. The size is computed BEFORE encoding
// so an oversize listing is rejected without the large frame allocation (RR-6).
func listDirFrame(clean string, entries []proto.DirEntry) ([]byte, bool) {
	if listDirPayloadSize(clean, entries) > proto.MaxControlPayload {
		return nil, false
	}
	return proto.Encode(proto.ListDirResponse{Path: clean, Entries: entries}), true
}

// listDirPayloadSize returns the exact wire payload size of a LIST_DIR_RESPONSE
// without allocating it: path:str + count:u32, then each entry as name:str +
// kind:u8 + size:u64 + mtime:u64 + flags:u8.
func listDirPayloadSize(clean string, entries []proto.DirEntry) int {
	size := 2 + len(clean) + 4
	for _, e := range entries {
		size += 2 + len(e.Name) + 1 + 8 + 8 + 1
	}
	return size
}

func (s *Server) handleStat(sess *Session, req proto.StatRequest) {
	clean, entry, err := s.vfs.Stat(req.Path)
	if err != nil {
		s.sendErr(sess, vfs.CodeOf(err))
		return
	}
	sess.sendMsg(proto.StatResponse{Path: clean, Entry: entry})
}

func (s *Server) handleChecksum(sess *Session, req proto.ChecksumRequest) {
	clean, algo, sum, err := s.vfs.Checksum(req.Path)
	if err != nil {
		s.sendErr(sess, vfs.CodeOf(err))
		return
	}
	sess.sendMsg(proto.ChecksumResponse{Path: clean, Algo: algo, Checksum: sum})
}

// idleWatchdog closes the connection once it has been idle past idle_timeout_s,
// unless a transfer is active. Closing unblocks the reader for a clean teardown,
// so an idle deadline never fires in the middle of a frame read (RR-1, CR-03).
func (s *Server) idleWatchdog(sess *Session) {
	t := time.NewTicker(idleCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-sess.done:
			return
		case <-t.C:
			idle := time.Duration(s.hub.Current().Limits.IdleTimeoutS) * time.Second
			if s.reapable(sess, idle) {
				sess.conn.Close()
				return
			}
		}
	}
}

// reapable reports whether the idle watchdog may close the connection now: it
// must be idle past the timeout AND neither streaming a download nor running a
// synchronous request handler, so long legitimate work is never reaped mid-flight
// (CR-03, R3-6).
func (s *Server) reapable(sess *Session, idle time.Duration) bool {
	if sess.downloading.Load() || sess.inFlight.Load() {
		return false
	}
	return sess.idleFor() >= idle
}

func (s *Server) sendErr(sess *Session, code proto.ErrCode) bool {
	return sess.sendMsg(proto.Error{Code: code, Message: code.String()})
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
