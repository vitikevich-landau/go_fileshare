package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestEscCancelConfirm(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.panels = [2]*Panel{newPanel(false, "l", "/"), newPanel(true, "r", "/")}
	m.active = 1

	cancelled := false
	m.transfer = &transferState{name: "big.bin"}
	m.dlCancel = func() { cancelled = true }

	// Esc asks first; it must not cancel yet.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyEsc})
	if !m.dlCancelConfirm {
		t.Fatal("Esc during a transfer should ask for confirmation")
	}
	if cancelled {
		t.Fatal("Esc must not cancel before confirmation")
	}

	// A non-'y' key dismisses without cancelling.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if m.dlCancelConfirm || cancelled {
		t.Fatal("any non-'y' key should dismiss without cancelling")
	}

	// Re-arm and confirm with 'y'.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyEsc})
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if !cancelled {
		t.Fatal("'y' should cancel the download")
	}
}

func TestConnectionLostPlaque(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.screen = screenCommander
	m.panels = [2]*Panel{newPanel(false, "l", "/"), newPanel(true, "r", "/")}
	m.active = 1
	m.link = linkReconnect

	if out := m.viewCommander(); !strings.Contains(out, "CONNECTION LOST") {
		t.Fatalf("reconnecting should show a connection-lost plaque, got:\n%s", out)
	}
}
