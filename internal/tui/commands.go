package tui

import (
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

// listRemoteCmd fetches a remote directory listing.
func listRemoteCmd(c *client.Client, path string) tea.Cmd {
	return func() tea.Msg {
		clean, entries, err := c.ListDir(path)
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
