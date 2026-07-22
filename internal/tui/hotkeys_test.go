package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHotkeys(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.panels = [2]*Panel{newPanel(false, "l", "/"), newPanel(true, "r", "/")}
	m.active = 1
	m.panels[1].SetEntries([]Entry{
		{Name: "a.txt", Size: 100},
		{Name: "b.txt", Size: 300},
	}, false)

	// '*' inverts selection: both files become selected.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("*")})
	if n := len(m.panels[1].Selected); n != 2 {
		t.Fatalf("invert-select selected %d, want 2", n)
	}

	// F2 cycles to size sort (largest first): b.txt(300) moves ahead of a.txt.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyF2})
	if m.panels[1].Sort != sortBySize {
		t.Fatalf("sort = %v, want size", m.panels[1].Sort)
	}
	if m.panels[1].Entries[0].Name != "b.txt" {
		t.Fatalf("size sort put %q first, want b.txt", m.panels[1].Entries[0].Name)
	}

	// Ctrl+O toggles the fullscreen log.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyCtrlO})
	if !m.fullLog {
		t.Fatal("Ctrl+O should enable the fullscreen log")
	}
	m.fullLog = false

	// F3 opens the info box; any key dismisses it.
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyF3})
	if m.infoBox == nil {
		t.Fatal("F3 should open the info box")
	}
	m.handleCommanderKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if m.infoBox != nil {
		t.Fatal("any key should dismiss the info box")
	}
}
