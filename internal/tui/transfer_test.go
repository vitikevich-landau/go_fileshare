package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestTransferRateAndQueue(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m.transfer = &transferState{
		name:      "big.bin",
		received:  500_000,
		total:     1_000_000,
		startedAt: time.Now().Add(-2 * time.Second),
	}
	m.queue = []downloadJob{{name: "next.bin"}}

	out := m.renderTransfer()
	if !strings.Contains(out, "/s") {
		t.Fatalf("transfer line missing speed: %q", out)
	}
	if !strings.Contains(out, "ETA") {
		t.Fatalf("transfer line missing ETA: %q", out)
	}
	if !strings.Contains(out, "+1 queued") {
		t.Fatalf("transfer line missing queue indicator: %q", out)
	}

	// With no active transfer but a non-empty queue, show the queued count.
	m.transfer = nil
	if got := m.renderTransfer(); !strings.Contains(got, "1 queued") {
		t.Fatalf("idle queue indicator missing: %q", got)
	}
}
