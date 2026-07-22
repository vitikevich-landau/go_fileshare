package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// handleAdmin dispatches an admin message. The request loop only reaches this
// for role=admin sessions (dispatch.MinRole), so authorization is enforced on
// the server regardless of the client UI (docs/tz/05-admin.md §1).
func (s *Server) handleAdmin(sess *Session, m proto.Message) {
	switch req := m.(type) {
	case proto.AdminGetConfig:
		s.adminGetConfig(sess)
	case proto.AdminSet:
		s.adminSet(sess, req)
	case proto.AdminListClients:
		s.adminListClients(sess)
	case proto.AdminKick:
		s.adminKick(sess, req)
	case proto.AdminStats:
		s.adminStats(sess)
	case proto.AdminShutdown:
		s.adminShutdown(sess, req)
	case proto.AdminReloadUsers:
		s.adminReloadUsers(sess)
	default:
		sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "unknown admin message"})
	}
}

func (s *Server) adminReloadUsers(sess *Session) {
	dropped, err := s.ReloadUsers()
	if err != nil {
		sess.sendMsg(proto.AdminReloadUsersResult{OK: false, Message: err.Error()})
		return
	}
	s.log.Info("admin reload users", "admin", sess.Login(), "dropped_sessions", dropped)
	s.BroadcastNotice(proto.SevInfo, fmt.Sprintf("%s reloaded users (%d session(s) dropped)", sess.Login(), dropped))
	sess.sendMsg(proto.AdminReloadUsersResult{OK: true, Message: fmt.Sprintf("reloaded; %d session(s) dropped", dropped)})
}

func (s *Server) adminGetConfig(sess *Session) {
	b, err := json.Marshal(s.hub.Current().AdminView())
	if err != nil {
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	sess.sendMsg(proto.AdminConfig{JSON: b})
}

func (s *Server) adminSet(sess *Session, req proto.AdminSet) {
	if err := s.hub.Set(req.Key, req.Value); err != nil {
		sess.sendMsg(proto.AdminSetResult{OK: false, Message: err.Error()})
		return
	}
	// hub.Set already persisted + broadcast EVENT_CONFIG via onConfigChange.
	s.log.Info("admin config change", "admin", sess.Login(), "ip", sess.IP, "key", req.Key, "value", req.Value)
	s.BroadcastNotice(proto.SevInfo, fmt.Sprintf("%s set %s = %s", sess.Login(), req.Key, req.Value))
	sess.sendMsg(proto.AdminSetResult{OK: true, Message: "applied"})
}

func (s *Server) adminListClients(sess *Session) {
	now := time.Now()
	sessions := s.reg.list()
	clients := make([]proto.ClientInfo, 0, len(sessions))
	for _, sn := range sessions {
		up := now.Sub(sn.startedAt).Seconds()
		bytes := sn.bytes.Load()
		var speed uint64
		if up > 0 {
			speed = uint64(float64(bytes) / up) // average over the session
		}
		clients = append(clients, proto.ClientInfo{
			SessionID:   sn.ID,
			Login:       sn.Login(),
			IP:          sn.IP,
			Role:        sn.Role(),
			CurrentPath: sn.CurPath(),
			BytesSent:   bytes,
			SpeedBps:    speed,
		})
	}
	sess.sendMsg(proto.AdminClients{Clients: clients})
}

func (s *Server) adminKick(sess *Session, req proto.AdminKick) {
	if req.SessionID == sess.ID {
		sess.sendMsg(proto.AdminKickResult{OK: false, Message: "cannot kick your own session"})
		return
	}
	target, ok := s.reg.get(req.SessionID)
	if !ok {
		sess.sendMsg(proto.AdminKickResult{OK: false, Message: "no such session"})
		return
	}
	s.log.Info("admin kick", "admin", sess.Login(), "target_session", req.SessionID, "target_login", target.Login())
	s.BroadcastNotice(proto.SevWarn, fmt.Sprintf("%s kicked session %d (%s)", sess.Login(), req.SessionID, target.Login()))
	target.conn.Close() // unblocks its reader/writer; the handler tears down
	sess.sendMsg(proto.AdminKickResult{OK: true, Message: fmt.Sprintf("kicked session %d", req.SessionID)})
}

func (s *Server) adminStats(sess *Session) {
	lim := s.hub.Current().Limits
	files, bytes := s.vfs.ShareStats() // cached; walks in the background at most every 30s
	sess.sendMsg(proto.AdminStatsResponse{
		UptimeS:         uint64(time.Since(s.start).Seconds()),
		BytesSent:       s.bytesSent.Load(),
		Completed:       s.completed.Load(),
		ActiveConns:     uint64(s.activeConns.Load()),
		ActiveDownloads: uint64(s.activeDownloads.Load()),
		SharedFiles:     files,
		SharedBytes:     bytes,
		PerClientBps:    lim.PerClientBps,
		GlobalBps:       lim.GlobalBps,
		Version:         s.version,
	})
}

func (s *Server) adminShutdown(sess *Session, req proto.AdminShutdown) {
	s.BroadcastNotice(proto.SevWarn, fmt.Sprintf("server shutting down in %d seconds", req.GraceSeconds))
	s.log.Info("admin shutdown requested", "admin", sess.Login(), "grace_s", req.GraceSeconds)
	sess.sendMsg(proto.AdminShutdownResult{OK: true, Message: "shutting down"})
	// Cancel the accept loop after replying, so drain runs with the grace.
	go s.requestShutdown(req.GraceSeconds)
}
