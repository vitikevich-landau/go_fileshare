package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// View implements tea.Model.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 {
		return "loading…"
	}
	if m.screen == screenConnect {
		return m.viewConnect()
	}
	if m.admin {
		return m.viewAdmin()
	}
	return m.viewCommander()
}

func (m *Model) viewConnect() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colCyan).Render("  fileshare commander") + "\n\n")
	b.WriteString("  Host:  " + m.fields[0].View() + "    Port: " + m.fields[1].View() + "\n")
	b.WriteString("  Login: " + m.fields[2].View() + "\n")
	b.WriteString("  Pass:  " + m.fields[3].View() + "\n\n")

	if m.hasProfiles() {
		b.WriteString("  Saved profiles:\n")
		for i, pr := range m.profiles.Profiles {
			cursor := "    "
			line := fmt.Sprintf("%s (%s@%s:%d)", pr.Name, pr.Login, pr.Host, pr.Port)
			if m.focus == m.profilesFocus() && i == m.profileCursor {
				cursor = "  > "
				line = styActiveTitle.Render(line)
			}
			b.WriteString(cursor + line + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(styDim.Render("  [Enter] connect   [Tab] next field   [Esc] quit") + "\n")
	if m.connecting {
		b.WriteString("\n  " + m.status + "\n")
	}
	if m.connectErr != "" {
		b.WriteString("\n  " + styErr.Render("error: "+m.connectErr) + "\n")
	}
	return b.String()
}

func (m *Model) viewCommander() string {
	colW := (m.width - 3) / 2
	if colW < 12 {
		colW = 12
	}
	left := m.renderPanelLines(0, colW)
	right := m.renderPanelLines(1, colW)

	var b strings.Builder
	rows := len(left)
	for i := 0; i < rows; i++ {
		b.WriteString(left[i])
		b.WriteString(styDim.Render(" │ "))
		b.WriteString(right[i])
		b.WriteString("\n")
	}

	b.WriteString(m.renderOpLog(4))
	b.WriteString(m.renderTransfer() + "\n")
	b.WriteString(m.renderPrompt() + "\n")
	b.WriteString(m.renderFbar())
	return b.String()
}

// renderPanelLines returns title + panelRows entry lines + status, each colW wide.
func (m *Model) renderPanelLines(idx, colW int) []string {
	p := m.panels[idx]
	active := idx == m.active

	titleText := p.Label
	if p.Remote {
		link := "○"
		switch m.link {
		case linkUp:
			link = "●"
		case linkReconnect:
			link = "◐"
		}
		titleText = fmt.Sprintf("%s %s", link, p.Label)
	}
	titleStyle := styInactiveTitle
	if active {
		titleStyle = styActiveTitle
	}
	lines := []string{titleStyle.Render(fit(titleText, colW-2))}

	for row := 0; row < m.panelRows; row++ {
		idxE := p.Top + row
		if idxE >= len(p.Entries) {
			lines = append(lines, strings.Repeat(" ", colW))
			continue
		}
		e := p.Entries[idxE]
		text := entryLine(e, colW)
		style := entryStyle(e, active && idxE == p.Cursor, p.Selected[e.Name])
		lines = append(lines, style.Render(text))
	}

	status := fmt.Sprintf("%d files, %s", p.FileCount(), formatSize(p.TotalSize()))
	if n := p.NewCount(); n > 0 {
		status += fmt.Sprintf(" · new: %d", n)
	}
	lines = append(lines, styDim.Render(fit(status, colW)))
	return lines
}

func entryStyle(e Entry, cursor, selected bool) lipgloss.Style {
	switch {
	case cursor:
		return styCursor
	case selected:
		return stySelect
	case e.IsNew:
		return styNew
	case e.HasPart:
		return styPart
	case e.IsDir:
		return styDir
	default:
		return styDim
	}
}

func entryLine(e Entry, w int) string {
	marker := " "
	if e.IsNew {
		marker = "*"
	} else if e.HasPart {
		marker = "~"
	}
	name := e.Name
	if e.IsDir {
		name = "/" + e.Name
	}
	if e.IsUp {
		name = "/.."
	}
	size := ""
	if !e.IsDir {
		size = formatSize(e.Size)
	}
	date := ""
	if e.Mtime > 0 {
		date = time.Unix(e.Mtime, 0).Format("06-01-02")
	}
	right := fmt.Sprintf("%8s %8s", size, date)
	nameW := w - 1 - lipgloss.Width(right) - 1
	if nameW < 4 {
		nameW = 4
	}
	return fit(marker+fit(name, nameW)+" "+right, w)
}

func (m *Model) renderOpLog(n int) string {
	var b strings.Builder
	start := len(m.opLog) - n
	if start < 0 {
		start = 0
	}
	shown := m.opLog[start:]
	for i := 0; i < n; i++ {
		if i < len(shown) {
			ll := shown[i]
			var st lipgloss.Style
			switch ll.kind {
			case lineErr:
				st = styErr
			case lineOK:
				st = styOK
			case lineEvent:
				st = styEvent
			default:
				st = styDim
			}
			b.WriteString(st.Render(fit(ll.text, m.width)) + "\n")
		} else {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (m *Model) renderTransfer() string {
	if m.transfer == nil {
		return strings.Repeat(" ", 0)
	}
	pct := 0.0
	if m.transfer.total > 0 {
		pct = float64(m.transfer.received) / float64(m.transfer.total)
	}
	bar := m.prog.ViewAs(pct)
	return fmt.Sprintf("%s %s %s/%s", bar, m.transfer.name,
		formatSize(m.transfer.received), formatSize(m.transfer.total))
}

func (m *Model) renderPrompt() string {
	path := m.activePanel().Path
	login := m.profile.Login
	if login == "" {
		login = "anon"
	}
	return styPrompt.Render(fmt.Sprintf("%s@%s:%s$", login, m.serverName, path))
}

func (m *Model) renderFbar() string {
	keys := "F1 Help  F5 Get  Ctrl+R Refresh  Ctrl+N Seen  Tab Switch  F10 Quit"
	if m.role == 2 { // admin
		keys = "F1 Help  F5 Get  Ctrl+R Refresh  F9 Admin  Tab Switch  F10 Quit"
	}
	return styFbar.Render(fit(keys, m.width))
}

// fit truncates or pads s to exactly w runes.
func fit(s string, w int) string {
	if w < 0 {
		w = 0
	}
	r := []rune(s)
	if len(r) > w {
		if w >= 1 {
			return string(r[:w-1]) + "…"
		}
		return ""
	}
	return s + strings.Repeat(" ", w-len(r))
}
