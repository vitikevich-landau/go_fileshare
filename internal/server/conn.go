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

// handshake проводит рукопожатие HELLO → HELLO_OK → AUTH_REQUEST →
// AUTH_OK|AUTH_FAIL под общим дедлайном. Возвращает true, когда сессия
// аутентифицирована (docs/tz/09-go-port.md §4.5, §5.5). Пока идёт рукопожатие,
// PING отвечается PONG, а кадры читаются с МАЛЫМ потолком тела, чтобы
// неаутентифицированный клиент не занял память огромным заголовком длины (CR-05).
func (s *Server) handshake(sess *Session) bool {
	cur := s.hub.Current()
	deadline := time.Now().Add(time.Duration(cur.Limits.HandshakeTimeoutS) * time.Second)
	_ = sess.conn.SetReadDeadline(deadline)

	// Фаза 1: ждём HELLO (PING по пути отвечаем). До-аутентификационные кадры
	// читаются с малым потолком тела (CR-05).
	var hello proto.Hello
	for {
		typ, payload, err := proto.ReadFrameLimited(sess.conn, proto.HandshakeMaxPayload)
		if err != nil {
			// Неразбираемый первый кадр (например, клиент v1) — по мере сил отвергаем.
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

	// Выдаём challenge (случайный вызов для этого рукопожатия).
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

	// Фаза 2: ждём AUTH_REQUEST (PING по пути отвечаем), всё ещё под малым
	// до-аутентификационным потолком тела (CR-05).
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

// authenticate проверяет доказательство клиента (или принимает любой логин в
// bootstrap-режиме без входа), применяет бан по IP и лимит сессий на пользователя
// и отвечает AUTH_OK или AUTH_FAIL. Возвращает, удалась ли аутентификация.
func (s *Server) authenticate(sess *Session, req proto.AuthRequest, cur *config.Settings) bool {
	now := time.Now()
	if s.guard.Banned(sess.IP, now) {
		s.log.Warn("authentication rejected: banned", "ip", sess.IP, "login", req.Login)
		sess.sendMsg(proto.AuthFail{Reason: proto.AuthFailBanned, Message: "too many attempts, temporarily banned"})
		return false
	}

	// Bootstrap без входа: любой логин становится ADMIN.
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

	// Атомарно применяем лимит сессий на пользователя и помечаем сессию
	// аутентифицированной, чтобы параллельные входы одного пользователя не смогли
	// все пройти проверку (CR-06).
	if !s.reg.reserveUserSlot(sess, req.Login, role, cur.Limits.MaxSessionsPerUser) {
		s.log.Warn("authentication rejected: too many sessions", "ip", sess.IP, "login", req.Login)
		sess.sendMsg(proto.AuthFail{Reason: proto.AuthFailTooManySession, Message: "too many concurrent sessions"})
		return false
	}
	s.guard.Success(sess.IP)
	sess.sendMsg(proto.AuthOk{Role: role, SessionID: sess.ID, Motd: cur.Server.Motd})
	return true
}

// serveRequests — цикл запросов ПОСЛЕ аутентификации. Чтения блокируются БЕЗ
// покадрового дедлайна (чтобы дедлайн не сработал посреди кадра и не
// рассинхронизировал поток, RR-1); отдельный сторож простоя обеспечивает
// idle-тайм-аут, ЗАКРЫВАЯ соединение, что разблокирует чтение для чистого
// teardown. Активная передача от тайм-аута освобождена (CR-03).
func (s *Server) serveRequests(sess *Session) {
	_ = sess.conn.SetReadDeadline(time.Time{}) // снимаем дедлайн рукопожатия
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
				// Ошибка кадрирования/протокола: по мере сил уведомляем и закрываем.
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
			// Битое тело рвёт только это соединение.
			sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "malformed payload"})
			return
		}

		// На время работы обработчика помечаем соединение «в работе», чтобы
		// синхронный запрос, идущий дольше idle_timeout_s (checksum большого файла,
		// большой листинг, админ-вызов), не был скошен сторожем простоя на полпути
		// (R3-6). touch() после даёт ответу свежее окно простоя.
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
			mask &^= proto.SubConfig // EVENT_CONFIG только для админа (CR-07)
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
		// Всё прочее от клиента — нарушение протокола.
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
		// Листинг, который вышел бы за лимит кадра, отвергаем контролируемой
		// ошибкой, а не огромным кадром, который порвал бы соединение (CR-10).
		// Пагинация — будущее расширение протокола.
		s.log.Warn("directory listing exceeds frame limit", "path", clean, "entries", len(entries))
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	sess.send(frame)
}

// listDirFrame кодирует LIST_DIR_RESPONSE, возвращая ok=false, если его тело
// вышло бы за лимит кадра. Размер считается ДО кодирования, поэтому слишком
// большой листинг отвергается без выделения большого кадра (RR-6).
func listDirFrame(clean string, entries []proto.DirEntry) ([]byte, bool) {
	if listDirPayloadSize(clean, entries) > proto.MaxControlPayload {
		return nil, false
	}
	return proto.Encode(proto.ListDirResponse{Path: clean, Entries: entries}), true
}

// listDirPayloadSize возвращает точный размер тела LIST_DIR_RESPONSE на проводе,
// НЕ выделяя его: path:str + count:u32, затем каждая запись как name:str +
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

// idleWatchdog закрывает соединение, как только оно простояло дольше
// idle_timeout_s, если не идёт передача. Закрытие разблокирует читателя для
// чистого teardown, поэтому idle-дедлайн никогда не срабатывает посреди чтения
// кадра (RR-1, CR-03).
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

// reapable сообщает, вправе ли сторож простоя закрыть соединение прямо сейчас:
// оно должно простаивать дольше тайм-аута И не отдавать закачку, И не выполнять
// синхронный обработчик — так долгая законная работа не будет скошена на полпути
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
