package tui

import (
	"errors"
	"fmt"
	"path"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

var errClientClosed = errors.New("connection closed")

const (
	pollInterval  = 150 * time.Millisecond
	heartbeatEach = 20 * time.Second
	maxBackoff    = 30 * time.Second
)

// eventForwarder returns a client event handler that forwards async frames to
// the model's events channel without blocking (a dropped event just misses a
// live refresh; Ctrl+R recovers).
func (m *Model) eventForwarder() func(proto.Message) {
	ev := m.events
	return func(msg proto.Message) {
		select {
		case ev <- eventMsg{m: msg}:
		default:
		}
	}
}

// subscribeFS subscribes to events on the current client: filesystem events for
// everyone, plus config/notice streams for admins (for the admin log).
func (m *Model) subscribeFS() {
	mask := proto.SubFS
	if m.role == proto.RoleAdmin {
		mask |= proto.SubConfig | proto.SubNotice
	}
	m.clientMu.Lock()
	c := m.client
	if c != nil {
		_ = c.Subscribe(mask)
	}
	m.clientMu.Unlock()
}

// startPump launches the background goroutine that receives events while idle
// and sends heartbeats (docs/tz/04-tui-client.md §7).
func (m *Model) startPump() {
	m.stopPump()
	stop := make(chan struct{})
	m.pumpStop = stop
	go m.runPump(stop)
}

func (m *Model) stopPump() {
	if m.pumpStop != nil {
		close(m.pumpStop)
		m.pumpStop = nil
	}
}

func (m *Model) runPump(stop chan struct{}) {
	lastPing := time.Now()
	for {
		select {
		case <-stop:
			return
		default:
		}

		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			time.Sleep(pollInterval)
			continue
		}
		_, err := c.PollEvents(pollInterval)
		if err == nil && time.Since(lastPing) > heartbeatEach {
			err = c.Ping()
			lastPing = time.Now()
		}
		m.clientMu.Unlock()

		if err != nil && isConnLost(err) {
			select {
			case m.events <- connLostMsg{err: err}:
			case <-stop:
			}
			return
		}
	}
}

// onEvent applies an async frame: it logs and, for a change in the currently
// shown remote directory, refreshes that panel while keeping the cursor.
func (m *Model) onEvent(pm proto.Message) tea.Cmd {
	switch e := pm.(type) {
	case proto.EventFs:
		verb := "changed"
		switch e.Op {
		case proto.FsCreated:
			verb = "appeared"
		case proto.FsRemoved:
			verb = "removed"
		}
		m.log(lineEvent, fmt.Sprintf("+ %s: %s (%s)", verb, e.Path, formatSize(e.Size)))
		rp := m.remotePanel()
		if rp != nil && path.Dir(e.Path) == rp.Path && !m.busy {
			m.remoteKeepCursor = rp.Cursor
			m.busy = true
			return m.listRemote(rp.Path)
		}
	case proto.EventNotice:
		m.log(lineInfo, "notice: "+e.Text)
		m.journal(lineEvent, "notice: "+e.Text)
	case proto.EventConfig:
		m.log(lineInfo, fmt.Sprintf("config: %s = %s", e.Key, e.NewValue))
		m.journal(lineInfo, fmt.Sprintf("config: %s = %s", e.Key, e.NewValue))
		m.onAdminConfigEvent(e) // live-update the settings tab if open
	}
	return nil
}

func (m *Model) remotePanel() *Panel {
	for i := range m.panels {
		if m.panels[i] != nil && m.panels[i].Remote {
			return m.panels[i]
		}
	}
	return nil
}

// beginReconnect tears down the dropped connection and schedules a reconnect
// attempt. It is idempotent while a reconnect is already in progress.
func (m *Model) beginReconnect(cause error) tea.Cmd {
	if m.reconnecting {
		return nil
	}
	m.reconnecting = true
	m.link = linkReconnect
	m.stopPump()
	m.clientMu.Lock()
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	m.clientMu.Unlock()
	m.busy = false
	m.transfer = nil
	m.queue = nil
	m.backoff = time.Second
	m.log(lineErr, fmt.Sprintf("connection lost (%v) — reconnecting…", cause))
	return m.reconnectCmd()
}

func (m *Model) reconnectCmd() tea.Cmd {
	delay := m.backoff
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	opts := client.Options{
		Login:        m.profile.Login,
		Password:     m.password,
		ClientName:   "fshare-commander",
		EventHandler: m.eventForwarder(),
	}
	return func() tea.Msg {
		time.Sleep(delay)
		c, err := client.Dial(addr, opts)
		if err != nil {
			return reconnectFailedMsg{err: err}
		}
		return reconnectedMsg{client: c}
	}
}

func (m *Model) onReconnected(msg reconnectedMsg) tea.Cmd {
	m.clientMu.Lock()
	m.client = msg.client
	m.clientMu.Unlock()
	m.reconnecting = false
	m.link = linkUp
	m.backoff = time.Second
	m.role = msg.client.Role()
	m.log(lineOK, "reconnected")
	m.subscribeFS()
	m.startPump()

	// Re-read the currently shown remote directory.
	rp := m.remotePanel()
	if rp != nil {
		m.remoteKeepCursor = rp.Cursor
		m.busy = true
		return m.listRemote(rp.Path)
	}
	return nil
}

func (m *Model) onReconnectFailed(msg reconnectFailedMsg) tea.Cmd {
	m.backoff *= 2
	if m.backoff > maxBackoff {
		m.backoff = maxBackoff
	}
	m.log(lineErr, fmt.Sprintf("reconnect failed (%v); retrying in %s", msg.err, m.backoff))
	return m.reconnectCmd()
}
