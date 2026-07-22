package tui

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	adminTabJournal  = 3
	adminTabCount    = 4
)

// confirmKind identifies which lifecycle action the admin confirmation modal is
// gating (docs/tz/05-admin.md §2.5 / §2.2).
type confirmKind int

const (
	confirmNone confirmKind = iota
	confirmShutdown
	confirmKick
)

// defaultShutdownGrace is used when the admin confirms a shutdown without an
// explicit "shutdown <seconds>" grace.
const defaultShutdownGrace = 10

// adminMenuItems are the F2 lifecycle actions (docs/tz/05-admin.md §2.5).
var adminMenuItems = []string{"Graceful shutdown", "Reload users"}

const (
	adminMenuShutdown = 0
	adminMenuReload   = 1
)

// journal appends one line to the admin Journal tab's live tail (bounded).
func (m *Model) journal(kind lineKind, text string) {
	m.adminJournal = append(m.adminJournal, logLine{kind: kind, text: time.Now().Format("15:04:05") + " " + text})
	if len(m.adminJournal) > 200 {
		m.adminJournal = m.adminJournal[len(m.adminJournal)-200:]
	}
}

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
type adminShutdownResultMsg struct {
	ok  bool
	msg string
	err error
}
type adminReloadResultMsg struct {
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

func (m *Model) adminReloadUsersCmd() tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminReloadResultMsg{err: errClientClosed}
		}
		ok, msg, err := c.AdminReloadUsers()
		m.clientMu.Unlock()
		return adminReloadResultMsg{ok: ok, msg: msg, err: err}
	}
}

func (m *Model) adminShutdownCmd(grace uint32) tea.Cmd {
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return adminShutdownResultMsg{err: errClientClosed}
		}
		ok, msg, err := c.AdminShutdown(grace)
		m.clientMu.Unlock()
		return adminShutdownResultMsg{ok: ok, msg: msg, err: err}
	}
}

// adminRefreshTab reloads the data for the current tab.
func (m *Model) adminRefreshTab() tea.Cmd {
	switch m.adminTab {
	case adminTabClients:
		return m.adminClientsCmd()
	case adminTabSettings:
		return m.adminConfigCmd()
	case adminTabJournal:
		return nil // passively accumulated from the event stream
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
	m.adminDetail = nil
	m.adminConfirm = confirmNone
	m.adminMenu = false
	return tea.Batch(m.adminStatsCmd(), m.adminClientsCmd(), m.adminConfigCmd())
}

func (m *Model) handleAdminKey(k tea.KeyMsg) tea.Cmd {
	if m.adminConfirm != confirmNone {
		return m.handleAdminConfirmKey(k)
	}
	if m.adminMenu {
		return m.handleAdminMenuKey(k)
	}
	if m.adminDetail != nil {
		if k.String() == "ctrl+c" {
			return m.quit()
		}
		m.adminDetail = nil // any other key dismisses the session-detail box
		return nil
	}
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
	case "4":
		m.adminTab, m.adminCursor = adminTabJournal, 0
		return nil
	case "tab":
		m.adminTab = (m.adminTab + 1) % adminTabCount
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
		switch m.adminTab {
		case adminTabSettings:
			return m.startEditSetting()
		case adminTabClients:
			m.showClientDetail()
		}
	case "f2":
		m.adminMenu = true
		m.adminMenuCursor = 0
		m.adminMsg = ""
		return nil
	case "f8", "k":
		if m.adminTab == adminTabClients {
			return m.kickSelected()
		}
	}
	return nil
}

// handleAdminMenuKey drives the F2 lifecycle menu (docs/tz/05-admin.md §2.5).
func (m *Model) handleAdminMenuKey(k tea.KeyMsg) tea.Cmd {
	switch k.String() {
	case "esc", "f2":
		m.adminMenu = false
		return nil
	case "ctrl+c":
		return m.quit()
	case "up":
		if m.adminMenuCursor > 0 {
			m.adminMenuCursor--
		}
	case "down":
		if m.adminMenuCursor < len(adminMenuItems)-1 {
			m.adminMenuCursor++
		}
	case "enter":
		m.adminMenu = false
		switch m.adminMenuCursor {
		case adminMenuShutdown:
			return m.startShutdownConfirm()
		case adminMenuReload:
			return m.adminReloadUsersCmd()
		}
	}
	return nil
}

// startShutdownConfirm opens the typed-word confirmation for a graceful
// shutdown (docs/tz/05-admin.md §2.5): the admin must type "shutdown".
func (m *Model) startShutdownConfirm() tea.Cmd {
	ti := textinput.New()
	ti.Placeholder = "shutdown [seconds]"
	ti.Focus()
	ti.Width = 24
	m.adminConfirmInput = ti
	m.adminConfirm = confirmShutdown
	m.adminMsg = ""
	return textinput.Blink
}

// handleAdminConfirmKey drives the confirmation modal (F2 shutdown / kick).
func (m *Model) handleAdminConfirmKey(k tea.KeyMsg) tea.Cmd {
	switch m.adminConfirm {
	case confirmShutdown:
		switch k.String() {
		case "esc":
			m.adminConfirm = confirmNone
			m.adminMsg = "shutdown cancelled"
			return nil
		case "enter":
			grace, ok := parseShutdownConfirm(m.adminConfirmInput.Value())
			if !ok {
				m.adminMsg = "type exactly 'shutdown' or 'shutdown <seconds>' to confirm"
				return nil
			}
			m.adminConfirm = confirmNone
			m.adminMsg = fmt.Sprintf("requesting shutdown (grace %ds)…", grace)
			return m.adminShutdownCmd(grace)
		default:
			var c tea.Cmd
			m.adminConfirmInput, c = m.adminConfirmInput.Update(k)
			return c
		}
	case confirmKick:
		switch k.String() {
		case "y", "enter":
			id := m.adminConfirmArg
			m.adminConfirm = confirmNone
			return m.adminKickCmd(id)
		default: // any other key (n/esc/…) cancels
			m.adminConfirm = confirmNone
			m.adminMsg = "kick cancelled"
			return nil
		}
	}
	return nil
}

// parseShutdownConfirm accepts ONLY exactly "shutdown" or "shutdown <seconds>"
// where <seconds> is a valid uint32. Any other form (wrong word, extra args,
// non-numeric or overflowing grace) is rejected so a destructive action is never
// confirmed by a typo silently falling back to the default grace.
func parseShutdownConfirm(s string) (grace uint32, ok bool) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 || len(f) > 2 || f[0] != "shutdown" {
		return 0, false
	}
	grace = defaultShutdownGrace
	if len(f) == 2 {
		n, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			return 0, false
		}
		grace = uint32(n)
	}
	return grace, true
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
	// Confirm before kicking (docs/tz/05-admin.md §2.2).
	m.adminConfirm = confirmKick
	m.adminConfirmArg = target.SessionID
	m.adminMsg = ""
	return nil
}

// showClientDetail opens the session-detail box for the selected client
// (docs/tz/05-admin.md §2.2, "Enter — детали сессии").
func (m *Model) showClientDetail() {
	if m.adminCursor < 0 || m.adminCursor >= len(m.adminClients) {
		return
	}
	c := m.adminClients[m.adminCursor] // snapshot, stable across refreshes
	m.adminDetail = &c
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
	tabs := []string{"1 Overview", "2 Clients", "3 Settings", "4 Journal"}
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
	case adminTabJournal:
		b.WriteString(m.renderAdminJournal())
	}

	if m.adminMsg != "" {
		b.WriteString("\n" + styEvent.Render(fit(m.adminMsg, m.width)) + "\n")
	}
	if m.adminEditing {
		b.WriteString("\n  set " + m.adminEditKey + " = " + m.adminInput.View() + "   [Enter apply · Esc cancel]\n")
	}
	if m.adminMenu {
		b.WriteString("\n" + m.renderAdminMenu())
	}
	if m.adminDetail != nil {
		b.WriteString("\n" + m.renderClientDetail())
	}
	switch m.adminConfirm {
	case confirmShutdown:
		b.WriteString("\n  " + styErr.Render("GRACEFUL SHUTDOWN") +
			" — type 'shutdown [seconds]' to confirm: " + m.adminConfirmInput.View() + "   [Enter · Esc cancel]\n")
	case confirmKick:
		b.WriteString("\n  " + styErr.Render(fmt.Sprintf("Kick session %d?", m.adminConfirmArg)) + "   [y confirm · any other key cancel]\n")
	}
	b.WriteString("\n" + styFbar.Render(fit("Tab/1-4 switch · ↑↓ move · Enter edit · F8/k kick · F2 menu · Ctrl+R refresh · Esc back", m.width)))
	return b.String()
}

// renderAdminMenu draws the F2 lifecycle menu (shutdown / reload users).
func (m *Model) renderAdminMenu() string {
	var b strings.Builder
	b.WriteString(styActiveTitle.Render(" Lifecycle ") + "\n")
	for i, item := range adminMenuItems {
		line := fit("  "+item, 30)
		if i == m.adminMenuCursor {
			b.WriteString(styCursor.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString(styDim.Render("  ↑↓ move · Enter select · Esc close") + "\n")
	return b.String()
}

// renderAdminJournal shows the live tail of server notices and config changes
// (docs/tz/05-admin.md §2.4). Newest lines are at the bottom.
func (m *Model) renderAdminJournal() string {
	if len(m.adminJournal) == 0 {
		return styDim.Render("  (no events yet — logins, kicks and config changes appear here)") + "\n"
	}
	rows := m.height - 8
	if rows < 3 {
		rows = 3
	}
	start := len(m.adminJournal) - rows
	if start < 0 {
		start = 0
	}
	var b strings.Builder
	for _, ll := range m.adminJournal[start:] {
		var st = styDim
		switch ll.kind {
		case lineErr:
			st = styErr
		case lineOK:
			st = styOK
		case lineEvent:
			st = styEvent
		}
		b.WriteString("  " + st.Render(fit(ll.text, m.width-2)) + "\n")
	}
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
		fmt.Sprintf("  Share:         %d files", s.SharedFiles),
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

func (m *Model) renderClientDetail() string {
	c := m.adminDetail
	lines := []string{
		styActiveTitle.Render(fit(fmt.Sprintf(" Session %d", c.SessionID), 20)),
		fmt.Sprintf("  Login:   %s", c.Login),
		fmt.Sprintf("  IP:      %s", c.IP),
		fmt.Sprintf("  Role:    %s", c.Role.String()),
		fmt.Sprintf("  Path:    %s", c.CurrentPath),
		fmt.Sprintf("  Sent:    %s", formatSize(c.BytesSent)),
		fmt.Sprintf("  Speed:   %s", limitStr(c.SpeedBps)),
		styDim.Render("  [any key to close]"),
	}
	return strings.Join(lines, "\n") + "\n"
}

func limitStr(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return formatSize(bps) + "/s"
}
