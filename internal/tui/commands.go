package tui

import (
	"context"
	"errors"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
)

// dialCmd connects and authenticates in the background.
func dialCmd(addr string, opts client.Options, prof Profile) tea.Cmd {
	return func() tea.Msg {
		c, err := client.Dial(addr, opts)
		if err != nil {
			return connectErrMsg{err: err}
		}
		return connectedMsg{
			client:     c,
			serverName: c.ServerName(),
			motd:       c.Motd(),
			role:       c.Role(),
			profile:    prof,
		}
	}
}

// listRemote fetches a remote directory listing, holding the client mutex so it
// cannot race with the event pump or a download.
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

// waitForActivity blocks until the next message arrives on the events channel.
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
