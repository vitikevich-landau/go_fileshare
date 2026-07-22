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
		if ok && !enabled {
			reason = proto.AuthFailUserDisabled
		}
		banned := s.guard.Fail(sess.IP, now, time.Duration(cur.Limits.AuthFailBanS)*time.Second)
		msg := "authentication failed"
		if banned {
			msg = "authentication failed; too many attempts, temporarily banned"
		}
		sess.sendMsg(proto.AuthFail{Reason: reason, Message: msg})
		return false
	}

	// Enforce the per-user session cap before admitting.
	if cur.Limits.MaxSessionsPerUser > 0 && s.reg.countUser(req.Login) >= cur.Limits.MaxSessionsPerUser {
		sess.sendMsg(proto.AuthFail{Reason: proto.AuthFailTooManySession, Message: "too many concurrent sessions"})
		return false
	}

	sess.setAuthed(req.Login, role)
	s.guard.Success(sess.IP)
	sess.sendMsg(proto.AuthOk{Role: role, SessionID: sess.ID, Motd: cur.Server.Motd})
	return true
}

// serveRequests is the post-auth request loop. It blocks on reads in bounded
// polls so that an active transfer is never reaped by the idle timeout, while a
// genuinely idle connection is still closed once idle_timeout_s elapses (CR-03).
func (s *Server) serveRequests(sess *Session) {
	lastActivity := time.Now()
	for {
		cur := s.hub.Current()
		idle := time.Duration(cur.Limits.IdleTimeoutS) * time.Second
		poll := idle
		if poll > idlePollCap {
			poll = idlePollCap
		}
		_ = sess.conn.SetReadDeadline(time.Now().Add(poll))

		typ, payload, err := proto.ReadFrame(sess.conn)
		if err != nil {
			if isTimeout(err) {
				// An active download is activity: reset the idle clock and keep
				// serving. Otherwise disconnect only after a real idle window.
				if sess.downloading.Load() {
					lastActivity = time.Now()
					continue
				}
				if time.Since(lastActivity) < idle {
					continue
				}
				return // genuinely idle past idle_timeout_s
			}
			if !errors.Is(err, io.EOF) {
				// Framing/protocol error: best-effort notice, then close.
				sess.trySendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "malformed frame"})
			}
			return
		}
		lastActivity = time.Now()

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

		s.dispatch(sess, m)
	}
}

func (s *Server) dispatch(sess *Session, m proto.Message) {
	switch req := m.(type) {
	case proto.Ping:
		sess.sendMsg(proto.Pong{})
	case proto.Subscribe:
		sess.subMask.Store(req.Mask)
	case proto.ListDirRequest:
		s.handleList(sess, req)
	case proto.StatRequest:
		s.handleStat(sess, req)
	case proto.ChecksumRequest:
		s.handleChecksum(sess, req)
	case proto.DownloadRequest:
		s.startDownload(sess, req)
	case proto.DownloadCancel:
		sess.cancelDownload()
	case proto.AdminGetConfig, proto.AdminSet, proto.AdminListClients,
		proto.AdminKick, proto.AdminStats, proto.AdminShutdown:
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
	sess.sendMsg(proto.ListDirResponse{Path: clean, Entries: entries})
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

func (s *Server) sendErr(sess *Session, code proto.ErrCode) bool {
	return sess.sendMsg(proto.Error{Code: code, Message: code.String()})
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
