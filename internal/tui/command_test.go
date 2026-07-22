package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestCommandLine(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.panels = [2]*Panel{newPanel(false, "local", "/tmp"), newPanel(true, "srv", "/")}
	m.active = 1
	m.panels[1].SetEntries([]Entry{{Name: "file.bin", Size: 10, Mtime: 1700000000}}, false)

	// ':' opens the command line.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(":")})
	if !m.cmdMode {
		t.Fatal("':' should open command mode")
	}

	// "info <file>" logs the file's metadata and closes the line.
	m.cmdInput.SetValue("info file.bin")
	m.handleCmdKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.cmdMode {
		t.Fatal("Enter should close command mode")
	}
	if joined := strings.Join(logTexts(m.opLog), " "); !strings.Contains(joined, "info: file.bin") {
		t.Fatalf("expected an info line, got: %s", joined)
	}

	// An unknown verb is reported and returns no command.
	if cmd := m.execCommand("frobnicate"); cmd != nil {
		t.Fatal("unknown command should not return a cmd")
	}
	if !strings.Contains(strings.Join(logTexts(m.opLog), " "), "unknown command") {
		t.Fatal("unknown command should be logged")
	}

	// Esc cancels the command line.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(":")})
	m.handleCmdKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.cmdMode {
		t.Fatal("Esc should close command mode")
	}
}
