package tui

import (
	"context"
	"errors"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
)

// dialCmd подключается и аутентифицируется В ФОНЕ (как tea.Cmd, вне UI-потока).
// gen помечает результат, чтобы устаревшую попытку (например, отменённую Esc)
// можно было проигнорировать.
func dialCmd(addr string, opts client.Options, prof Profile, gen int) tea.Cmd {
	return func() tea.Msg {
		c, err := client.Dial(addr, opts)
		if err != nil {
			return connectErrMsg{err: err, gen: gen}
		}
		return connectedMsg{
			client:     c,
			serverName: c.ServerName(),
			motd:       c.Motd(),
			role:       c.Role(),
			profile:    prof,
			gen:        gen,
		}
	}
}

// listRemote запрашивает листинг удалённого каталога, удерживая мьютекс клиента,
// чтобы не было гонки с насосом событий или закачкой (блокирующий транспорт —
// однопользовательский).
func (m *Model) listRemote(path string) tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return remoteErrMsg{err: errors.New("not connected")}
		}
		clean, entries, err := c.ListDir(path)
		m.clientMu.Unlock()
		if err != nil {
			return remoteErrMsg{err: err}
		}
		return remoteListingMsg{path: clean, entries: entries}
	}
}

// waitForActivity — команда, блокирующая до прихода следующего сообщения в канал
// events. Так асинхронные кадры из фоновых горутин (насос, закачка) попадают в
// цикл Update. После каждого такого сообщения слушателя нужно перевзвести (см.
// fromChannel), иначе следующее сообщение из канала не будет прочитано.
func waitForActivity(events chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-events }
}

// isConnLost reports whether err indicates a dropped connection rather than an
// application-level (server ERROR / AUTH_FAIL) failure.
func isConnLost(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var re *client.RemoteError
	if errors.As(err, &re) {
		return false
	}
	var ae *client.AuthError
	if errors.As(err, &ae) {
		return false
	}
	return true
}
