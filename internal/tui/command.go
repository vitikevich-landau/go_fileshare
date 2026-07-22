package tui

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// cmdHelp lists the interactive command line's verbs (docs/tz/04-tui-client.md).
const cmdHelp = "commands: cd <path> · get [file…] · info [file] · refresh · disconnect · help · quit"

// enterCmdMode focuses the bottom command line (opened with ":").
func (m *Model) enterCmdMode() {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Focus()
	w := m.width - 16
	if w < 8 {
		w = 8
	}
	ti.Width = w
	m.cmdInput = ti
	m.cmdMode = true
}

// handleCmdKey drives the command line: Enter runs it, Esc cancels.
func (m *Model) handleCmdKey(k tea.KeyMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		m.cmdMode = false
		return nil
	case "enter":
		line := strings.TrimSpace(m.cmdInput.Value())
		m.cmdMode = false
		return m.execCommand(line)
	default:
		var c tea.Cmd
		m.cmdInput, c = m.cmdInput.Update(k)
		return c
	}
}

// execCommand parses and runs one command-line entry.
func (m *Model) execCommand(line string) tea.Cmd {
	if line == "" {
		return nil
	}
	fields := strings.Fields(line)
	verb, args := fields[0], fields[1:]
	switch verb {
	case "cd":
		if len(args) == 0 {
			m.log(lineErr, "usage: cd <path>")
			return nil
		}
		return m.cmdCd(args[0])
	case "get":
		return m.cmdGet(args)
	case "info":
		return m.cmdInfo(args)
	case "refresh":
		return m.refreshActive()
	case "disconnect":
		return m.doDisconnect()
	case "help":
		m.log(lineInfo, cmdHelp)
		return nil
	case "quit", "exit":
		return m.quit()
	default:
		m.log(lineErr, "unknown command: "+verb+" ("+cmdHelp+")")
		return nil
	}
}

// cmdCd changes the active panel's directory (absolute or relative).
func (m *Model) cmdCd(arg string) tea.Cmd {
	p := m.activePanel()
	if p.Remote {
		target := arg
		if !strings.HasPrefix(arg, "/") {
			target = path.Join(p.Path, arg)
		}
		return m.cdRemote(target)
	}
	target := arg
	if !filepath.IsAbs(arg) {
		target = filepath.Join(p.Path, arg)
	}
	m.cdLocal(m.active, target)
	return nil
}

// cmdGet queues downloads by name; with no args it downloads the selection.
func (m *Model) cmdGet(names []string) tea.Cmd {
	p := m.activePanel()
	if !p.Remote {
		m.log(lineErr, "get works on the remote panel")
		return nil
	}
	other := m.panels[1-m.active]
	if other.Remote {
		m.log(lineErr, "no local destination panel")
		return nil
	}
	if len(names) == 0 {
		return m.download()
	}
	added := 0
	for _, name := range names {
		e, ok := p.findFile(name)
		if !ok {
			m.log(lineErr, "no such file: "+name)
			continue
		}
		m.queue = append(m.queue, downloadJob{
			remote: path.Join(p.Path, e.Name),
			local:  filepath.Join(other.Path, e.Name),
			name:   e.Name,
		})
		added++
	}
	if added > 0 && !m.busy {
		m.startNext()
	}
	return nil
}

// cmdInfo logs metadata for a named file (or the cursor entry).
func (m *Model) cmdInfo(names []string) tea.Cmd {
	p := m.activePanel()
	var (
		e  Entry
		ok bool
	)
	if len(names) > 0 {
		e, ok = p.findFile(names[0])
	} else {
		e, ok = p.Current()
	}
	if !ok {
		m.log(lineErr, "info: no such file")
		return nil
	}
	when := ""
	if e.Mtime > 0 {
		when = time.Unix(e.Mtime, 0).Format("2006-01-02 15:04")
	}
	m.log(lineInfo, fmt.Sprintf("info: %s · %s · %s", e.Name, formatSize(e.Size), when))
	return nil
}

// doDisconnect closes the connection and returns to the connect screen. It must
// not wait on clientMu (an active download holds it for the whole transfer), so
// it cancels the transfer and any pending reconnect first, then closes the
// socket directly — which unblocks the download's read. m.client is only ever
// assigned on this (Update) goroutine, so reading it here without the lock is
// safe (same rationale as quit()).
func (m *Model) doDisconnect() tea.Cmd {
	m.stopPump()
	if m.dlCancel != nil {
		m.dlCancel() // cancel the active transfer's context
	}
	m.reconnecting = false // invalidate any pending reconnect (guarded in onReconnected)
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	m.transfer = nil
	m.dlCancel = nil
	m.queue = nil
	m.busy = false
	m.link = linkDown
	m.screen = screenConnect
	m.log(lineInfo, "disconnected")
	return nil
}
