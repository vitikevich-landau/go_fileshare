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
	m.status = "connecting…"

	// Esc while connecting cancels the attempt without quitting the program.
	m.handleConnectKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.connecting {
		t.Fatal("Esc should stop the connecting state")
	}
	if !m.connectAborted {
		t.Fatal("Esc should flag the attempt as aborted")
	}
	if m.quitting {
		t.Fatal("Esc during a connect must not quit the program")
	}

	// The aborted attempt's late error is swallowed, not shown as a dial failure.
	m.Update(connectErrMsg{err: errClientClosed})
	if m.connectAborted {
		t.Fatal("the late result should clear the aborted flag")
	}
	if strings.Contains(m.connectErr, "closed") {
		t.Fatalf("aborted attempt should not surface its error, got %q", m.connectErr)
	}
}
