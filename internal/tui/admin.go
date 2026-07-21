package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// configKey mirrors config.KeyInfo for decoding ADMIN_CONFIG without importing
// the server config package into the TUI.
type configKey struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Hot   bool   `json:"hot"`
}

const (
	adminTabOverview = 0
	adminTabClients  = 1
	adminTabSettings = 2
)

// ---- admin async messages (Cmd results) ----

type adminStatsMsg struct {
	stats proto.AdminStatsResponse
	err   error
}
type adminClientsMsg struct {
	clients []proto.ClientInfo
	err     error
}
type adminConfigMsg struct {
	rows []configKey
	err  error
}
type adminSetResultMsg struct {
	key string
	ok  bool
	msg string
	err error
}
type adminKickResultMsg struct {
	ok  bool
	msg string
	err error
}

// ---- commands (serialize on the client mutex) ----

func (m *Model) adminStatsCmd() tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminStatsMsg{err: errClientClosed}
		}
		st, err := c.AdminStats()
		m.clientMu.Unlock()
		return adminStatsMsg{stats: st, err: err}
	}
}

func (m *Model) adminClientsCmd() tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminClientsMsg{err: errClientClosed}
		}
		cl, err := c.AdminListClients()
		m.clientMu.Unlock()
		return adminClientsMsg{clients: cl, err: err}
	}
}

func (m *Model) adminConfigCmd() tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminConfigMsg{err: errClientClosed}
		}
		raw, err := c.AdminGetConfig()
		m.clientMu.Unlock()
		if err != nil {
			return adminConfigMsg{err: err}
		}
		var rows []configKey
		if jerr := json.Unmarshal(raw, &rows); jerr != nil {
			return adminConfigMsg{err: jerr}
		}
		return adminConfigMsg{rows: rows}
	}
}

func (m *Model) adminSetCmd(key, value string) tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminSetResultMsg{key: key, err: errClientClosed}
		}
		ok, msg, err := c.AdminSet(key, value)
		m.clientMu.Unlock()
		return adminSetResultMsg{key: key, ok: ok, msg: msg, err: err}
	}
}

func (m *Model) adminKickCmd(id uint64) tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminKickResultMsg{err: errClientClosed}
		}
		ok, msg, err := c.AdminKick(id)
		m.clientMu.Unlock()
		return adminKickResultMsg{ok: ok, msg: msg, err: err}
	}
}

// adminRefreshTab reloads the data for the current tab.
func (m *Model) adminRefreshTab() tea.Cmd {
	switch m.adminTab {
	case adminTabClients:
		return m.adminClientsCmd()
	case adminTabSettings:
		return m.adminConfigCmd()
	default:
		return m.adminStatsCmd()
	}
}

// openAdmin enters the admin panel (admins only) and loads all three tabs.
func (m *Model) openAdmin() tea.Cmd {
	if m.role != proto.RoleAdmin {
		m.log(lineErr, "admin: insufficient permissions")
		return nil
	}
	m.admin = true
	m.adminTab = adminTabOverview
	m.adminCursor = 0
	m.adminMsg = ""
	return tea.Batch(m.adminStatsCmd(), m.adminClientsCmd(), m.adminConfigCmd())
}

func (m *Model) handleAdminKey(k tea.KeyMsg) tea.Cmd {
	if m.adminEditing {
		switch k.String() {
		case "esc":
			m.adminEditing = false
			return nil
		case "enter":
			key, val := m.adminEditKey, m.adminInput.Value()
			m.adminEditing = false
			return m.adminSetCmd(key, val)
		default:
			var c tea.Cmd
			m.adminInput, c = m.adminInput.Update(k)
			return c
		}
	}

	switch k.String() {
	case "esc", "f9":
		m.admin = false
		return nil
	case "ctrl+c":
		return m.quit()
	case "f10", "q":
		m.admin = false
		return nil
	case "1":
		m.adminTab, m.adminCursor = adminTabOverview, 0
		return m.adminStatsCmd()
	case "2":
		m.adminTab, m.adminCursor = adminTabClients, 0
		return m.adminClientsCmd()
	case "3":
		m.adminTab, m.adminCursor = adminTabSettings, 0
		return m.adminConfigCmd()
	case "tab":
		m.adminTab = (m.adminTab + 1) % 3
		m.adminCursor = 0
		return m.adminRefreshTab()
	case "ctrl+r":
		return m.adminRefreshTab()
	case "up":
		if m.adminCursor > 0 {
			m.adminCursor--
		}
	case "down":
		if m.adminCursor < m.adminListLen()-1 {
			m.adminCursor++
		}
	case "enter":
		if m.adminTab == adminTabSettings {
			return m.startEditSetting()
		}
	case "f8", "k":
		if m.adminTab == adminTabClients {
			return m.kickSelected()
		}
	}
	return nil
}

func (m *Model) adminListLen() int {
	switch m.adminTab {
	case adminTabClients:
		return len(m.adminClients)
	case adminTabSettings:
		return len(m.adminConfig)
	}
	return 0
}

func (m *Model) startEditSetting() tea.Cmd {
	if m.adminCursor < 0 || m.adminCursor >= len(m.adminConfig) {
		return nil
	}
	row := m.adminConfig[m.adminCursor]
	if !row.Hot {
		m.adminMsg = fmt.Sprintf("%s is restart-only and cannot be changed over the network", row.Key)
		return nil
	}
	ti := textinput.New()
	ti.SetValue(row.Value)
	ti.Focus()
	ti.Width = 30
	m.adminInput = ti
	m.adminEditKey = row.Key
	m.adminEditing = true
	return textinput.Blink
}

func (m *Model) kickSelected() tea.Cmd {
	if m.adminCursor < 0 || m.adminCursor >= len(m.adminClients) {
		return nil
	}
	target := m.adminClients[m.adminCursor]
	if m.client != nil && target.SessionID == m.client.SessionID() {
		m.adminMsg = "cannot kick your own session"
		return nil
	}
	return m.adminKickCmd(target.SessionID)
}

// adminErr reports an admin op error, escalating a connection loss to reconnect.
func (m *Model) adminErr(err error) tea.Cmd {
	if isConnLost(err) {
		m.admin = false
		return m.beginReconnect(err)
	}
	m.adminMsg = "error: " + err.Error()
	return nil
}

// onAdminConfigEvent applies an EVENT_CONFIG to the loaded settings view.
func (m *Model) onAdminConfigEvent(e proto.EventConfig) {
	for i := range m.adminConfig {
		if m.adminConfig[i].Key == e.Key {
			m.adminConfig[i].Value = e.NewValue
			return
		}
	}
}

// ---- rendering ----

func (m *Model) viewAdmin() string {
	var b strings.Builder
	tabs := []string{"1 Overview", "2 Clients", "3 Settings"}
	var header []string
	for i, tname := range tabs {
		if i == m.adminTab {
			header = append(header, styActiveTitle.Render(tname))
		} else {
			header = append(header, styInactiveTitle.Render(tname))
		}
	}
	b.WriteString(styActiveTitle.Render(fit(" ADMIN: "+m.serverName, 20)) + "  " + strings.Join(header, " ") + "\n\n")

	switch m.adminTab {
	case adminTabOverview:
		b.WriteString(m.renderAdminOverview())
	case adminTabClients:
		b.WriteString(m.renderAdminClients())
	case adminTabSettings:
		b.WriteString(m.renderAdminSettings())
	}

	if m.adminMsg != "" {
		b.WriteString("\n" + styEvent.Render(fit(m.adminMsg, m.width)) + "\n")
	}
	if m.adminEditing {
		b.WriteString("\n  set " + m.adminEditKey + " = " + m.adminInput.View() + "   [Enter apply · Esc cancel]\n")
	}
	b.WriteString("\n" + styFbar.Render(fit("Tab/1/2/3 switch · ↑↓ move · Enter edit · F8/k kick · Ctrl+R refresh · Esc back", m.width)))
	return b.String()
}

func (m *Model) renderAdminOverview() string {
	s := m.adminStats
	up := time.Duration(s.UptimeS) * time.Second
	lines := []string{
		fmt.Sprintf("  Uptime:        %s", up),
		fmt.Sprintf("  Version:       %s", s.Version),
		fmt.Sprintf("  Connections:   %d", s.ActiveConns),
		fmt.Sprintf("  Active dloads: %d", s.ActiveDownloads),
		fmt.Sprintf("  Bytes sent:    %s", formatSize(s.BytesSent)),
		fmt.Sprintf("  Completed:     %d", s.Completed),
		fmt.Sprintf("  per-client lim: %s", limitStr(s.PerClientBps)),
		fmt.Sprintf("  global lim:     %s", limitStr(s.GlobalBps)),
	}
	return strings.Join(lines, "\n") + "\n"
}

func (m *Model) renderAdminClients() string {
	var b strings.Builder
	b.WriteString(styDim.Render(fmt.Sprintf("  %-6s %-12s %-16s %-6s %-10s %s", "id", "login", "ip", "role", "sent", "path")) + "\n")
	for i, c := range m.adminClients {
		line := fmt.Sprintf("  %-6d %-12s %-16s %-6s %-10s %s",
			c.SessionID, c.Login, c.IP, c.Role.String(), formatSize(c.BytesSent), c.CurrentPath)
		line = fit(line, m.width)
		if i == m.adminCursor {
			b.WriteString(styCursor.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func (m *Model) renderAdminSettings() string {
	var b strings.Builder
	for i, row := range m.adminConfig {
		mark := "[hot]    "
		if !row.Hot {
			mark = "[restart]"
		}
		line := fmt.Sprintf("  %-30s %-14s %s", row.Key, row.Value, mark)
		line = fit(line, m.width)
		switch {
		case i == m.adminCursor:
			b.WriteString(styCursor.Render(line) + "\n")
		case !row.Hot:
			b.WriteString(styDim.Render(line) + "\n")
		default:
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func limitStr(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return formatSize(bps) + "/s"
}
