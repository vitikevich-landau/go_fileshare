package server

import (
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// ReloadUsers перечитывает users.json и сбрасывает живые сессии тех
// пользователей, которых больше нет или которые отключены
// (docs/tz/03-server-daemon.md §3.3). Возвращает число сброшенных сессий.
// Вызывается по SIGHUP и по запросу админа (ADMIN_RELOAD_USERS).
func (s *Server) ReloadUsers() (int, error) {
	if s.users == nil {
		return 0, nil
	}
	if err := s.users.Reload(); err != nil {
		return 0, err
	}
	return s.dropDisabledSessions(), nil
}

// dropDisabledSessions закрывает каждую аутентифицированную сессию, чей
// пользователь теперь отсутствует или отключён. В bootstrap-режиме без входа
// (пустая БД) разрешён любой логин, поэтому ничего не сбрасывается.
func (s *Server) dropDisabledSessions() int {
	if s.users.Empty() {
		return 0
	}
	n := 0
	for _, sn := range s.reg.list() {
		login := sn.Login()
		if login == "" {
			continue // ещё идёт рукопожатие, пока не аутентифицирован
		}
		if _, _, enabled, ok := s.users.Lookup(login); ok && enabled {
			continue
		}
		s.log.Warn("dropping session: user disabled or removed", "session", sn.ID, "login", login)
		s.BroadcastNotice(proto.SevWarn, fmt.Sprintf("session %d (%s) dropped: user disabled", sn.ID, login))
		sn.conn.Close() // разблокирует его читателя/писателя; handler свернёт всё
		n++
	}
	return n
}
