package server

import (
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// ReloadUsers re-reads users.json and drops the live sessions of any user that
// is no longer present or has been disabled (docs/tz/03-server-daemon.md §3.3).
// It returns the number of sessions dropped.
func (s *Server) ReloadUsers() (int, error) {
	if s.users == nil {
		return 0, nil
	}
	if err := s.users.Reload(); err != nil {
		return 0, err
	}
	return s.dropDisabledSessions(), nil
}

// dropDisabledSessions closes every authenticated session whose user is now
// absent or disabled. In the no-auth bootstrap (empty DB) every login is
// allowed, so nothing is dropped.
func (s *Server) dropDisabledSessions() int {
	if s.users.Empty() {
		return 0
	}
	n := 0
	for _, sn := range s.reg.list() {
		login := sn.Login()
		if login == "" {
			continue // still handshaking, not yet authenticated
		}
		if _, _, enabled, ok := s.users.Lookup(login); ok && enabled {
			continue
		}
		s.log.Warn("dropping session: user disabled or removed", "session", sn.ID, "login", login)
		s.BroadcastNotice(proto.SevWarn, fmt.Sprintf("session %d (%s) dropped: user disabled", sn.ID, login))
		sn.conn.Close() // unblocks its reader/writer; the handler tears down
		n++
	}
	return n
}
