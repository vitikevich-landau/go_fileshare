package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// adminFixture builds an admin model populated enough to exercise every tab and
// modal, including wide-character (CJK) session data that would break naive
// rune-based width math.
func adminFixture() *Model {
	m := New(Profile{})
	m.role = proto.RoleAdmin
	m.admin = true
	m.serverName = "vps.example.com"
	m.link = linkUp
	m.adminStats = proto.AdminStatsResponse{
		UptimeS: 363132, Version: "go-2.0.1", ActiveConns: 12, ActiveDownloads: 3,
		BytesSent: 871_234_567_890, Completed: 1204, SharedFiles: 8421, PerClientBps: 10_000_000,
	}
	m.adminClients = []proto.ClientInfo{
		{SessionID: 1, Login: "vit", IP: "10.0.0.2", Role: proto.RoleAdmin, CurrentPath: "/"},
		{SessionID: 42, Login: "田中太郎", IP: "10.0.0.9", Role: proto.RoleUser,
			CurrentPath: "/媒体/视频/连续剧/第一季/存档/very/long/path/here", BytesSent: 999, SpeedBps: 5000},
	}
	m.adminConfig = []configKey{
		{Key: "limits.per_client_bps", Value: "10000000", Hot: true},
		{Key: "server.port", Value: "5555", Hot: false},
	}
	m.journal(lineEvent, "notice: kicked session 7 (bob)")
	return m
}

// TestAdminFrameFitsTerminal is the load-bearing layout contract: viewAdmin must
// render a frame of at most height lines, each at most width display columns —
// for every tab, every modal, and wide-character content, across a matrix of
// terminal sizes down to degenerate ones. Overlaid modals must not escape the
// frame (regression guard for the width/height overlay fixes).
func TestAdminFrameFitsTerminal(t *testing.T) {
	sizes := []struct{ w, h int }{
		{100, 30}, {80, 24}, {70, 20}, {64, 17}, {50, 20}, {44, 20}, {40, 12}, {30, 10}, {50, 6}, {20, 5},
	}
	states := []struct {
		name  string
		setup func(*Model)
	}{
		{"overview", func(m *Model) { m.adminTab = adminTabOverview }},
		{"clients", func(m *Model) { m.adminTab = adminTabClients; m.adminCursor = 1 }},
		{"settings", func(m *Model) { m.adminTab = adminTabSettings; m.adminCursor = 0 }},
		{"journal", func(m *Model) { m.adminTab = adminTabJournal }},
		{"toast", func(m *Model) { m.adminTab = adminTabSettings; m.adminMsg = "applied: limits.per_client_bps" }},
		{"modal-kick", func(m *Model) { m.adminTab = adminTabClients; m.adminConfirm = confirmKick; m.adminConfirmArg = 42 }},
		{"modal-shutdown", func(m *Model) {
			m.startShutdownConfirm()
			m.adminConfirmInput.SetValue("shutdown 30")
		}},
		{"modal-menu", func(m *Model) { m.adminMenu = true }},
		{"modal-detail", func(m *Model) { m.adminTab = adminTabClients; m.adminDetail = &m.adminClients[1] }},
		{"modal-edit", func(m *Model) { m.adminTab = adminTabSettings; m.adminCursor = 0; m.startEditSetting() }},
	}

	for _, sz := range sizes {
		for _, st := range states {
			m := adminFixture()
			m.Update(tea.WindowSizeMsg{Width: sz.w, Height: sz.h})
			st.setup(m)

			out := m.viewAdmin()
			lines := strings.Split(out, "\n")
			if len(lines) > sz.h {
				t.Errorf("%s @ %dx%d: frame has %d lines > height %d", st.name, sz.w, sz.h, len(lines), sz.h)
			}
			for i, l := range lines {
				if lw := lipgloss.Width(l); lw > sz.w {
					t.Errorf("%s @ %dx%d: line %d is %d cols > width %d:\n%q", st.name, sz.w, sz.h, i, lw, sz.w, l)
				}
			}
		}
	}
}

// TestAdminKickAcceptsUppercaseY guards the kick-confirm keycap fix: the modal
// hint shows "Y", so Shift+Y (key string "Y") must confirm, not cancel.
func TestAdminKickAcceptsUppercaseY(t *testing.T) {
	m := adminFixture()
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.adminTab = adminTabClients
	m.adminCursor = 1

	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	if m.adminConfirm != confirmKick {
		t.Fatal("k should open the kick confirm modal")
	}
	cmd := m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("Y")})
	if cmd == nil {
		t.Fatal("uppercase 'Y' should issue the kick command (matches the displayed keycap)")
	}
	if m.adminConfirm != confirmNone {
		t.Fatal("confirming with 'Y' should close the modal")
	}
}

// TestAdminSettingsCursorClampsOnShrink guards against a stale Settings cursor
// blanking the tab: if a config refresh returns fewer rows while the cursor sits
// past the new end, the scroll window would start beyond the slice and render
// nothing. The adminConfigMsg handler must clamp the cursor (as clients do).
func TestAdminSettingsCursorClampsOnShrink(t *testing.T) {
	m := adminFixture()
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.adminTab = adminTabSettings

	big := make([]configKey, 0, 10)
	for i := 0; i < 10; i++ {
		big = append(big, configKey{Key: "limits.key_" + string(rune('a'+i)), Value: "0", Hot: true})
	}
	m.adminConfig = big
	m.adminCursor = 9

	// Refresh returns just two rows; cursor 9 is now out of range.
	m.Update(adminConfigMsg{rows: big[:2]})
	if m.adminCursor >= len(m.adminConfig) {
		t.Fatalf("cursor %d not clamped into config len %d", m.adminCursor, len(m.adminConfig))
	}
	if !strings.Contains(m.viewAdmin(), "limits.key_a") {
		t.Fatal("settings tab rendered no rows after the config list shrank")
	}
}

// TestFitCols pads and truncates by display columns, unlike rune-based fit().
func TestFitCols(t *testing.T) {
	if got := lipgloss.Width(fitCols("abc", 10)); got != 10 {
		t.Errorf("fitCols pad width = %d, want 10", got)
	}
	// A CJK string of 5 wide runes = 10 columns; fit to 6 columns must yield 6.
	if got := lipgloss.Width(fitCols("媒体视频剧", 6)); got != 6 {
		t.Errorf("fitCols(wide, 6) width = %d, want 6", got)
	}
	if !strings.Contains(fitCols("媒体视频剧", 6), "…") {
		t.Error("fitCols should append an ellipsis when truncating")
	}
}
