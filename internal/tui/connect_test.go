package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestConnectCancel(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m.connecting = true
	m.connectGen = 5
	m.status = "connecting…"

	// Esc while connecting cancels the attempt without quitting the program.
	m.handleConnectKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.connecting {
		t.Fatal("Esc should stop the connecting state")
	}
	if m.connectGen == 5 {
		t.Fatal("Esc should bump the generation to invalidate the in-flight attempt")
	}
	if m.quitting {
		t.Fatal("Esc during a connect must not quit the program")
	}

	// A late result from the cancelled (old) generation is ignored.
	m.Update(connectErrMsg{err: errClientClosed, gen: 5})
	if strings.Contains(m.connectErr, "closed") {
		t.Fatalf("a stale-generation error must not surface, got %q", m.connectErr)
	}

	// A result from the CURRENT generation is accepted.
	m.connecting = true
	m.Update(connectErrMsg{err: errClientClosed, gen: m.connectGen})
	if !strings.Contains(m.connectErr, "closed") {
		t.Fatalf("current-generation error should surface, got %q", m.connectErr)
	}
	if m.connecting {
		t.Fatal("a current-generation error should end the connecting state")
	}
}
