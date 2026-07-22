package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func TestOpenAdminRequiresAdminRole(t *testing.T) {
	m := New(Profile{})
	m.role = proto.RoleUser
	if cmd := m.openAdmin(); cmd != nil || m.admin {
		t.Fatal("non-admin should not open the admin panel")
	}
	if !strings.Contains(strings.Join(logTexts(m.opLog), " "), "insufficient permissions") {
		t.Fatal("expected an insufficient-permissions log line")
	}

	m2 := New(Profile{})
	m2.role = proto.RoleAdmin
	if cmd := m2.openAdmin(); cmd == nil || !m2.admin {
		t.Fatal("admin should open the panel and load data")
	}
}

func TestAdminSettingsEditHotVsRestart(t *testing.T) {
	m := New(Profile{})
	m.role = proto.RoleAdmin
	m.admin = true
	m.adminTab = adminTabSettings
	m.adminConfig = []configKey{
		{Key: "server.port", Value: "5555", Hot: false},
		{Key: "limits.global_bps", Value: "0", Hot: true},
	}

	// Restart-only row cannot be edited.
	m.adminCursor = 0
	if cmd := m.startEditSetting(); cmd != nil || m.adminEditing {
		t.Fatal("restart-only key must not enter edit mode")
	}
	if !strings.Contains(m.adminMsg, "restart-only") {
		t.Fatalf("expected restart-only message, got %q", m.adminMsg)
	}

	// Hot row enters edit mode prefilled with the current value.
	m.adminCursor = 1
	if cmd := m.startEditSetting(); cmd == nil || !m.adminEditing {
		t.Fatal("hot key should enter edit mode")
	}
	if m.adminEditKey != "limits.global_bps" || m.adminInput.Value() != "0" {
		t.Fatalf("edit state = key %q value %q", m.adminEditKey, m.adminInput.Value())
	}
}

func TestAdminSetResultRefreshesAndReports(t *testing.T) {
	m := New(Profile{})
	m.role = proto.RoleAdmin
	m.admin = true

	// A rejected set reports the message and does not refresh.
	m.Update(adminSetResultMsg{key: "server.port", ok: false, msg: "restart-only"})
	if !strings.Contains(m.adminMsg, "rejected") {
		t.Fatalf("expected rejected message, got %q", m.adminMsg)
	}
}

func TestAdminJournalAccumulatesAndRenders(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true

	// EVENT_NOTICE (e.g. a kick) and EVENT_CONFIG feed the journal tail.
	m.Update(eventMsg{m: proto.EventNotice{Severity: proto.SevWarn, Text: "vit kicked session 7 (bob)"}})
	m.Update(eventMsg{m: proto.EventConfig{Key: "limits.global_bps", NewValue: "1000000"}})

	if len(m.adminJournal) != 2 {
		t.Fatalf("journal len = %d, want 2", len(m.adminJournal))
	}

	m.adminTab = adminTabJournal
	out := m.viewAdmin()
	for _, want := range []string{"4 Journal", "kicked session 7", "limits.global_bps = 1000000"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal view missing %q\n%s", want, out)
		}
	}
}

func TestAdminShutdownConfirmFlow(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true

	// F2 opens the lifecycle menu; Enter on the first item (Graceful shutdown)
	// opens the typed-word confirmation modal.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyF2})
	if !m.adminMenu {
		t.Fatal("F2 should open the lifecycle menu")
	}
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.adminConfirm != confirmShutdown {
		t.Fatalf("selecting Graceful shutdown should open the confirm modal, got %d", m.adminConfirm)
	}

	// A wrong confirmation word is rejected and keeps the modal open.
	m.adminConfirmInput.SetValue("halt")
	if cmd := m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyEnter}); cmd != nil {
		t.Fatal("a wrong confirm word must not issue a shutdown command")
	}
	if m.adminConfirm != confirmShutdown {
		t.Fatal("modal must stay open after a wrong word")
	}

	// The exact word with an explicit grace issues the command and closes it.
	m.adminConfirmInput.SetValue("shutdown 30")
	if cmd := m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyEnter}); cmd == nil {
		t.Fatal("the confirm word should issue a shutdown command")
	}
	if m.adminConfirm != confirmNone {
		t.Fatal("modal must close after confirming")
	}

	// Re-open via the menu, then Esc from a fresh confirm modal cancels it.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyF2})
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyEnter}) // select Graceful shutdown
	if m.adminConfirm != confirmShutdown {
		t.Fatal("menu should re-open the shutdown confirm")
	}
	if cmd := m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyEsc}); cmd != nil {
		t.Fatal("Esc must cancel the shutdown modal")
	}
	if m.adminConfirm != confirmNone {
		t.Fatal("Esc should close the modal")
	}
}

func TestParseShutdownConfirm(t *testing.T) {
	valid := map[string]uint32{
		"shutdown":      defaultShutdownGrace,
		"shutdown 0":    0,
		"shutdown 30":   30,
		"  shutdown 5 ": 5,
	}
	for in, want := range valid {
		if g, ok := parseShutdownConfirm(in); !ok || g != want {
			t.Errorf("parse(%q) = (%d,%v), want (%d,true)", in, g, ok, want)
		}
	}
	for _, in := range []string{
		"", "halt", "shutdownnow", "shutdown nope",
		"shutdown 10 20", "shutdown -1", "shutdown 99999999999999999999",
	} {
		if _, ok := parseShutdownConfirm(in); ok {
			t.Errorf("parse(%q) should be rejected", in)
		}
	}
}

func TestAdminMenuReloadUsers(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true

	// F2 opens the menu; item 1 is Reload users.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyF2})
	if !m.adminMenu {
		t.Fatal("F2 should open the lifecycle menu")
	}
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyDown}) // move to "Reload users"
	if m.adminMenuCursor != adminMenuReload {
		t.Fatalf("cursor = %d, want %d", m.adminMenuCursor, adminMenuReload)
	}
	cmd := m.handleAdminKey(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("selecting Reload users should return a command")
	}
	if m.adminMenu {
		t.Fatal("menu should close after selecting an item")
	}
}

func TestAdminKickConfirmFlow(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true
	m.adminTab = adminTabClients
	m.adminClients = []proto.ClientInfo{{SessionID: 7, Login: "bob"}}
	m.adminCursor = 0

	// 'k' opens the confirm modal rather than kicking immediately.
	if cmd := m.handleAdminKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")}); cmd != nil {
		t.Fatal("kick should open a confirm modal, not issue a command directly")
	}
	if m.adminConfirm != confirmKick || m.adminConfirmArg != 7 {
		t.Fatalf("expected kick confirm for session 7, got kind=%d arg=%d", m.adminConfirm, m.adminConfirmArg)
	}

	// Any non-'y' key cancels.
	m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if m.adminConfirm != confirmNone {
		t.Fatal("'n' should cancel the kick")
	}

	// Re-open and confirm with 'y' issues the kick command.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	if cmd := m.handleAdminConfirmKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}); cmd == nil {
		t.Fatal("'y' should issue the kick command")
	}
	if m.adminConfirm != confirmNone {
		t.Fatal("modal should close after confirming the kick")
	}
}

func TestAdminSessionDetail(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true
	m.adminTab = adminTabClients
	m.adminClients = []proto.ClientInfo{
		{SessionID: 7, Login: "bob", IP: "10.0.0.5", Role: proto.RoleUser, CurrentPath: "/video", BytesSent: 2048, SpeedBps: 1000},
	}
	m.adminCursor = 0

	// Enter opens the detail box for the selected session.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.adminDetail == nil || m.adminDetail.SessionID != 7 {
		t.Fatal("Enter on a client row should open its session detail")
	}
	out := m.viewAdmin()
	for _, want := range []string{"Session 7", "bob", "10.0.0.5", "/video"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q", want)
		}
	}

	// Any key dismisses the box.
	m.handleAdminKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if m.adminDetail != nil {
		t.Fatal("a key press should dismiss the session-detail box")
	}
}

func TestViewAdminRenders(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.role = proto.RoleAdmin
	m.admin = true
	m.serverName = "vps"
	m.adminStats = proto.AdminStatsResponse{UptimeS: 3600, Version: "go-2.0", ActiveConns: 3, PerClientBps: 5_000_000}
	m.adminClients = []proto.ClientInfo{{SessionID: 1, Login: "vit", IP: "10.0.0.2", Role: proto.RoleAdmin, BytesSent: 1024}}
	m.adminConfig = []configKey{{Key: "limits.global_bps", Value: "0", Hot: true}}

	// Overview
	out := m.viewAdmin()
	for _, want := range []string{"ADMIN: vps", "Overview", "go-2.0", "unlimited"} {
		if !strings.Contains(out, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	// Clients tab
	m.adminTab = adminTabClients
	if !strings.Contains(m.viewAdmin(), "vit") {
		t.Error("clients tab missing session login")
	}
	// Settings tab
	m.adminTab = adminTabSettings
	if s := m.viewAdmin(); !strings.Contains(s, "limits.global_bps") || !strings.Contains(s, "[hot]") {
		t.Error("settings tab missing config row")
	}
}
