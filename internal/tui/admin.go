package tui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// configKey зеркалит config.KeyInfo для разбора ADMIN_CONFIG, не втягивая в TUI
// серверный пакет config (клиент не должен зависеть от внутренностей сервера).
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
	ti := newThemedInput()
	ti.Placeholder = "shutdown [seconds]"
	ti.Focus()
	ti.Width = 24
	m.adminConfirmInput = ti
	m.adminConfirm = confirmShutdown
	m.adminMsg = ""
	return nil
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
		case "y", "Y", "enter":
			// Модалка показывает клавишу как "Y" (стиль неоновых кейкапов),
			// поэтому и Shift+Y (строка "Y") должен подтверждать, а не отменять.
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
	ti := newThemedInput()
	ti.SetValue(row.Value)
	ti.Focus()
	ti.Width = 30
	m.adminInput = ti
	m.adminEditKey = row.Key
	m.adminEditing = true
	return nil
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
//
// Каркас админ-панели (docs/tz/05-admin.md §2): экран занимает РОВНО
// width×height и собирается из фиксированных зон —
//
//	верхний бар (логотип · сервер · статус линка)          1 строка
//	рейка вкладок + подчёркивание активной                 2 строки
//	тело вкладки (карточки/таблица/журнал)                 height-5 строк
//	тост с результатом последней операции                  1 строка
//	футер с клавишами                                      1 строка
//
// Модальные окна (kick/shutdown/детали/меню/редактор) рисуются ПОВЕРХ кадра
// по центру через overlayCenter, а не приклеиваются к низу.

// adminTabNames — подписи вкладок в рейке (индекс = adminTab*).
var adminTabNames = [adminTabCount]string{"OVERVIEW", "CLIENTS", "SETTINGS", "JOURNAL"}

func (m *Model) viewAdmin() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	bodyH := h - 5
	if bodyH < 3 {
		bodyH = 3
	}

	var body []string
	switch m.adminTab {
	case adminTabClients:
		body = m.adminBodyClients(w, bodyH)
	case adminTabSettings:
		body = m.adminBodySettings(w, bodyH)
	case adminTabJournal:
		body = m.adminBodyJournal(w, bodyH)
	default:
		body = m.adminBodyOverview(w, bodyH)
	}
	for len(body) < bodyH {
		body = append(body, "")
	}
	body = body[:bodyH]

	lines := make([]string, 0, h)
	lines = append(lines, m.adminTopBar(w))
	lines = append(lines, m.adminTabRail(w)...)
	lines = append(lines, body...)
	lines = append(lines, m.adminToast())
	lines = append(lines, m.adminFooter(w))
	// На вырожденно низком терминале (h<8, где bodyH упёрся в пол 3) кадр
	// оказался бы выше экрана — стандартный рендерер Bubble Tea тогда оставил бы
	// только ПОСЛЕДНИЕ h строк, срезав верхний бар с индикатором вкладок и
	// линка. Обрезаем с низа (жертвуя футером/тостом), чтобы верх остался виден
	// и кадр был ровно h строк — это же значение уходит в overlayCenter.
	if len(lines) > h {
		lines = lines[:h]
	}
	for i := range lines {
		lines[i] = clipTo(lines[i], w)
	}
	frame := strings.Join(lines, "\n")

	if box := m.adminModal(w); box != "" {
		frame = overlayCenter(frame, box, w, len(lines))
	}
	return frame
}

// adminTopBar рисует верхнюю строку: логотип, имя сервера и статус связи/роли.
// На узких экранах правый блок деградирует посегментно (роль → текст линка),
// чтобы ничего не обрезалось посреди слова.
func (m *Model) adminTopBar(w int) string {
	left := " " + styAdminGlyph.Render("█▓▒░") + " " + styAdminLogo.Render("FSHARE ADMIN") +
		"  " + styDim.Render("◢") + " " + styAdminServer.Render(m.serverName)
	linkText := "ONLINE"
	switch m.link {
	case linkReconnect:
		linkText = "RECONNECT"
	case linkDown:
		linkText = "OFFLINE"
	}
	dot := linkColor(m.link).Render("●")
	for _, right := range []string{
		dot + " " + styDim.Render("LINK:"+linkText) + "  " + styRoleAdmin.Render("ROLE:ADMIN") + " ",
		dot + " " + styDim.Render("LINK:"+linkText) + " ",
		dot + " ",
	} {
		if gap := w - lipgloss.Width(left) - lipgloss.Width(right); gap >= 1 {
			return left + strings.Repeat(" ", gap) + right
		}
	}
	return left
}

// adminTabRail рисует рейку вкладок и линию-подчёркивание, в которой сегмент
// под активной вкладкой выделен неоном.
func (m *Model) adminTabRail(w int) []string {
	row := " "
	activeX, activeW := 1, 0
	x := 1
	for i, name := range adminTabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		var seg string
		if i == m.adminTab {
			seg = styTabActive.Render(label)
		} else {
			seg = styTabInactive.Render(label)
		}
		segW := lipgloss.Width(seg)
		if i == m.adminTab {
			activeX, activeW = x, segW
		}
		row += seg + " "
		x += segW + 1
	}

	if activeX+activeW > w {
		return []string{row, styRule.Render(strings.Repeat("─", w))}
	}
	rule := styRule.Render(strings.Repeat("─", activeX)) +
		styRuleActive.Render(strings.Repeat("━", activeW)) +
		styRule.Render(strings.Repeat("─", w-activeX-activeW))
	return []string{row, rule}
}

// card рисует одну карточку телеметрии фиксированной ширины w (рамка+заголовок
// с акцентным цветом, крупное значение, подпись).
func card(w int, accent lipgloss.Color, label, value, sub string) string {
	inner := w - 4 // рамка (2) + внутренние отступы (2)
	if inner < 6 {
		inner = 6
	}
	lines := []string{
		lipgloss.NewStyle().Bold(true).Foreground(accent).Render(fit(label, inner)),
		styCardValue.Render(fit(value, inner)),
		styDim.Render(fit(sub, inner)),
	}
	return styCardBox.Width(w - 2).Render(strings.Join(lines, "\n"))
}

// adminBodyOverview: сетка карточек телеметрии; на узких/низких экранах —
// компактный список тех же значений.
func (m *Model) adminBodyOverview(w, bodyH int) []string {
	s := m.adminStats
	up := time.Duration(s.UptimeS) * time.Second

	if w < 64 || bodyH < 17 {
		kv := func(k, v string) string {
			return "  " + styDim.Render(fit(k, 16)) + styText.Render(v)
		}
		return []string{
			"",
			kv("uptime", up.String()),
			kv("version", s.Version),
			kv("sessions", fmt.Sprintf("%d", s.ActiveConns)),
			kv("transfers", fmt.Sprintf("%d active · %d completed", s.ActiveDownloads, s.Completed)),
			kv("traffic", formatSize(s.BytesSent)),
			kv("share", fmt.Sprintf("%d files", s.SharedFiles)),
			kv("limit/client", limitStr(s.PerClientBps)),
			kv("limit/global", limitStr(s.GlobalBps)),
		}
	}

	cw := (w - 4) / 3
	half := (w - 3) / 2
	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		card(cw, colCyan, "SESSIONS", fmt.Sprintf("%d", s.ActiveConns), "active connections"),
		" ",
		card(cw, colPurple, "TRANSFERS", fmt.Sprintf("%d", s.ActiveDownloads), fmt.Sprintf("%d completed", s.Completed)),
		" ",
		card(cw, colTeal, "TRAFFIC", formatSize(s.BytesSent), "bytes sent total"),
	)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top,
		card(cw, colAmber, "SHARE", fmt.Sprintf("%d", s.SharedFiles), "files exported"),
		" ",
		card(cw, colMint, "UPTIME", up.String(), "since daemon start"),
		" ",
		card(cw, colBlue, "CORE", s.Version, "protocol v2"),
	)
	row3 := lipgloss.JoinHorizontal(lipgloss.Top,
		card(half, colCyan, "LIMIT / PER-CLIENT", limitStr(s.PerClientBps), "bandwidth per session"),
		" ",
		card(half, colPink, "LIMIT / GLOBAL", limitStr(s.GlobalBps), "bandwidth all sessions"),
	)

	out := []string{""}
	for _, block := range []string{row1, row2, row3} {
		for _, ln := range strings.Split(block, "\n") {
			out = append(out, " "+ln)
		}
	}
	return out
}

// adminScrollTop возвращает индекс первой видимой строки списка так, чтобы
// курсор всегда оставался в окне из visible строк.
func adminScrollTop(cursor, visible int) int {
	if visible < 1 {
		visible = 1
	}
	if cursor >= visible {
		return cursor - visible + 1
	}
	return 0
}

// adminBodyClients: таблица активных сессий с прокруткой и бейджами ролей.
func (m *Model) adminBodyClients(w, bodyH int) []string {
	out := []string{styTableHead.Render(fit(fmt.Sprintf("  %-6s %-14s %-16s %-7s %-10s %s",
		"ID", "LOGIN", "IP", "ROLE", "SENT", "PATH"), w))}
	if len(m.adminClients) == 0 {
		return append(out, "", styDim.Render("  no active sessions"))
	}

	var selfID uint64
	if m.client != nil {
		selfID = m.client.SessionID()
	}
	visible := bodyH - 1
	top := adminScrollTop(m.adminCursor, visible)
	end := top + visible
	if end > len(m.adminClients) {
		end = len(m.adminClients)
	}
	for i := top; i < end; i++ {
		c := m.adminClients[i]
		login := c.Login
		if selfID != 0 && c.SessionID == selfID {
			login += " (you)"
		}
		if i == m.adminCursor {
			row := fmt.Sprintf("  %-6d %-14.14s %-16s %-7s %-10s %s",
				c.SessionID, login, c.IP, strings.ToUpper(c.Role.String()), formatSize(c.BytesSent), c.CurrentPath)
			out = append(out, styCursor.Render(fitCols(row, w)))
			continue
		}
		roleSty := styBadgeRestart
		if c.Role == proto.RoleAdmin {
			roleSty = styRoleAdmin
		}
		row := "  " + styDim.Render(fmt.Sprintf("%-6d ", c.SessionID)) +
			styText.Render(fmt.Sprintf("%-14.14s ", login)) +
			styDim.Render(fmt.Sprintf("%-16s ", c.IP)) +
			roleSty.Render(fmt.Sprintf("%-7s ", strings.ToUpper(c.Role.String()))) +
			styPart.Render(fmt.Sprintf("%-10s ", formatSize(c.BytesSent))) +
			styDim.Render(c.CurrentPath)
		out = append(out, row)
	}
	return out
}

// adminBodySettings: живая конфигурация с бейджами hot/restart и прокруткой.
func (m *Model) adminBodySettings(w, bodyH int) []string {
	out := []string{styTableHead.Render(fit(fmt.Sprintf("  %-30s %-20s %s", "KEY", "VALUE", "MODE"), w))}
	if len(m.adminConfig) == 0 {
		return append(out, "", styDim.Render("  config not loaded yet — Ctrl+R to refresh"))
	}

	visible := bodyH - 1
	top := adminScrollTop(m.adminCursor, visible)
	end := top + visible
	if end > len(m.adminConfig) {
		end = len(m.adminConfig)
	}
	for i := top; i < end; i++ {
		row := m.adminConfig[i]
		badge := "⚡ hot"
		if !row.Hot {
			badge = "⟳ restart"
		}
		if i == m.adminCursor {
			line := fmt.Sprintf("  %-30s %-20s %s", row.Key, row.Value, badge)
			out = append(out, styCursor.Render(fitCols(line, w)))
			continue
		}
		keySty, valSty, badgeSty := styText, styAccent, styBadgeHot
		if !row.Hot {
			keySty, valSty, badgeSty = styDim, styDim, styBadgeRestart
		}
		out = append(out, "  "+keySty.Render(fmt.Sprintf("%-30s ", row.Key))+
			valSty.Render(fmt.Sprintf("%-20s ", row.Value))+
			badgeSty.Render(badge))
	}
	return out
}

// adminBodyJournal: живой хвост событий сервера (docs/tz/05-admin.md §2.4),
// новые строки внизу; каждая строка — метка времени + глиф вида события.
func (m *Model) adminBodyJournal(w, bodyH int) []string {
	if len(m.adminJournal) == 0 {
		return []string{"", styDim.Render("  no events yet — logins, kicks and config changes appear here")}
	}
	start := len(m.adminJournal) - bodyH
	if start < 0 {
		start = 0
	}
	var out []string
	for _, ll := range m.adminJournal[start:] {
		glyph, st := "▸", styDim
		switch ll.kind {
		case lineErr:
			glyph, st = "✕", styErr
		case lineOK:
			glyph, st = "✓", styOK
		case lineEvent:
			glyph, st = "◆", styEvent
		}
		ts, rest := ll.text, ""
		if sp := strings.IndexByte(ll.text, ' '); sp > 0 {
			ts, rest = ll.text[:sp], ll.text[sp+1:]
		}
		out = append(out, "  "+styDim.Render(ts)+" "+st.Render(glyph)+" "+st.Render(fit(rest, w-14)))
	}
	return out
}

// adminToast — строка результата последней операции над телом вкладки: успех
// зелёным, отказ/ошибка розовым, остальное янтарным.
func (m *Model) adminToast() string {
	if m.adminMsg == "" {
		return ""
	}
	glyph, st := "▸", styEvent
	switch {
	case strings.HasPrefix(m.adminMsg, "applied"):
		glyph, st = "✓", styOK
	case strings.HasPrefix(m.adminMsg, "error"),
		strings.HasPrefix(m.adminMsg, "rejected"),
		strings.HasPrefix(m.adminMsg, "cannot"):
		glyph, st = "✕", styErr
	}
	return " " + st.Render(glyph+" "+m.adminMsg)
}

// adminFooter — нижний бар с клавишами в стиле «неоновых кейкапов».
func (m *Model) adminFooter(w int) string {
	pairs := [][2]string{
		{"TAB", "tabs"}, {"1-4", "jump"}, {"↑↓", "move"}, {"ENTER", "open"},
		{"F8", "kick"}, {"F2", "lifecycle"}, {"^R", "refresh"}, {"ESC", "exit"},
	}
	var b strings.Builder
	b.WriteString(styFbar.Render(" "))
	for _, p := range pairs {
		b.WriteString(styFbarKey.Render(p[0]))
		b.WriteString(styFbar.Render(" " + p[1] + "  "))
	}
	s := b.String()
	if pad := w - lipgloss.Width(s); pad > 0 {
		s += styFbar.Render(strings.Repeat(" ", pad))
	}
	return s
}

// ---- модальные окна ----

// adminModal возвращает бокс активного модального окна ("" — окон нет). w —
// ширина кадра: модалка обязана уместиться в неё, иначе overlayCenter обрежет
// правый край окна прямо по контенту. Порядок ветвей зеркалит приоритет
// обработки клавиш в handleAdminKey.
func (m *Model) adminModal(w int) string {
	switch {
	case m.adminConfirm == confirmShutdown:
		return m.modalShutdown(w)
	case m.adminConfirm == confirmKick:
		return m.modalKick(w)
	case m.adminMenu:
		return m.modalMenu(w)
	case m.adminDetail != nil:
		return m.modalDetail(w)
	case m.adminEditing:
		return m.modalEdit(w)
	}
	return ""
}

// modalBox собирает рамку модального окна: заголовок, тело, подсказка внизу.
// danger переключает нейтральную (циан) рамку на опасную (розовую). Содержимое
// зажимается по ширине так, чтобы вся рамка уместилась в кадр w: рамка (2) +
// горизонтальные отступы Padding(1,2) (4) = 6 колонок оверхеда, поэтому контент
// режется до w-6 (ANSI-безопасно, чтобы не рвать стили). Длинные значения
// (путь сессии, значение настройки) усекаются, а не ломают вёрстку.
func modalBox(danger bool, title string, body []string, hint string, w int) string {
	titleSty, boxSty := styModalTitle, styModal
	if danger {
		titleSty, boxSty = styModalTitleDanger, styModalDanger
	}
	lines := []string{titleSty.Render(title), ""}
	lines = append(lines, body...)
	if hint != "" {
		lines = append(lines, "", styDim.Render(hint))
	}

	inner := w - 6
	if inner < 20 {
		inner = 20 // на совсем узком терминале модалка всё равно шире экрана —
	} //             overlayCenter обрежет её по краю, это вырожденный случай.
	for i, l := range lines {
		if lipgloss.Width(l) > inner {
			lines[i] = clipTo(l, inner)
		}
	}
	minW := 28
	if minW > inner {
		minW = inner
	}
	wMax := minW
	for _, l := range lines {
		if lw := lipgloss.Width(l); lw > wMax {
			wMax = lw
		}
	}
	for i, l := range lines {
		if pad := wMax - lipgloss.Width(l); pad > 0 {
			lines[i] = l + strings.Repeat(" ", pad)
		}
	}
	return boxSty.Render(strings.Join(lines, "\n"))
}

// modalMenu — меню жизненного цикла (F2): shutdown / reload users.
func (m *Model) modalMenu(w int) string {
	glyphs := []string{"⏻", "⟳"}
	var body []string
	for i, item := range adminMenuItems {
		line := fmt.Sprintf(" %s  %-22s", glyphs[i], item)
		if i == m.adminMenuCursor {
			line = styCursor.Render(line)
		} else {
			line = styText.Render(line)
		}
		body = append(body, line)
	}
	return modalBox(false, "LIFECYCLE", body, "↑↓ move · ENTER select · ESC close", w)
}

// modalKick — подтверждение отключения сессии (docs/tz/05-admin.md §2.2).
func (m *Model) modalKick(w int) string {
	target := fmt.Sprintf("session %d", m.adminConfirmArg)
	for _, c := range m.adminClients {
		if c.SessionID == m.adminConfirmArg {
			target = fmt.Sprintf("session %d (%s)", c.SessionID, c.Login)
			break
		}
	}
	return modalBox(true, "KICK SESSION",
		[]string{styText.Render("Disconnect " + target + "?")},
		"Y confirm · any other key cancel", w)
}

// modalShutdown — подтверждение остановки сервера вводом слова "shutdown".
func (m *Model) modalShutdown(w int) string {
	body := []string{
		styText.Render("The server will notify every client and stop."),
		styDim.Render("Type 'shutdown [seconds]' to confirm:"),
		"",
		" " + styAccent.Render("▸") + " " + m.adminConfirmInput.View(),
	}
	return modalBox(true, "GRACEFUL SHUTDOWN", body, "ENTER confirm · ESC cancel", w)
}

// modalDetail — карточка деталей выбранной сессии (Enter на вкладке Clients).
func (m *Model) modalDetail(w int) string {
	c := m.adminDetail
	kv := func(k, v string) string {
		return " " + styDim.Render(fit(k, 8)) + styText.Render(v)
	}
	body := []string{
		kv("login", c.Login),
		kv("ip", c.IP),
		kv("role", strings.ToUpper(c.Role.String())),
		kv("path", c.CurrentPath),
		kv("sent", formatSize(c.BytesSent)),
		kv("speed", limitStr(c.SpeedBps)),
	}
	return modalBox(false, fmt.Sprintf("SESSION %d", c.SessionID), body, "any key to close", w)
}

// modalEdit — редактор значения hot-параметра (Enter на вкладке Settings).
func (m *Model) modalEdit(w int) string {
	body := []string{
		styDim.Render("key ") + styText.Render(m.adminEditKey),
		"",
		" " + styAccent.Render("▸") + " " + m.adminInput.View(),
	}
	return modalBox(false, "EDIT SETTING", body, "ENTER apply · ESC cancel", w)
}

func limitStr(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return formatSize(bps) + "/s"
}
