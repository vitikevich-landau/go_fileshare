package tui

import (
	"errors"
	"io"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func TestIsConnLost(t *testing.T) {
	if isConnLost(nil) {
		t.Error("nil is not a connection loss")
	}
	if isConnLost(&client.RemoteError{Code: proto.ErrFileNotFound}) {
		t.Error("a server ERROR is not a connection loss")
	}
	if isConnLost(&client.AuthError{Reason: proto.AuthFailBadCredentials}) {
		t.Error("an auth failure is not a connection loss")
	}
	if !isConnLost(io.EOF) {
		t.Error("EOF should be a connection loss")
	}
	if !isConnLost(errors.New("connection reset by peer")) {
		t.Error("a network error should be a connection loss")
	}
}

func TestBeginReconnectIsIdempotent(t *testing.T) {
	m := New(Profile{Host: "h", Port: 5555, Login: "vit"})
	m.host, m.port = "h", 5555
	m.screen = screenCommander

	cmd := m.beginReconnect(io.EOF)
	if cmd == nil {
		t.Fatal("first beginReconnect should return a reconnect command")
	}
	if !m.reconnecting || m.link != linkReconnect {
		t.Fatalf("state after beginReconnect: reconnecting=%v link=%v", m.reconnecting, m.link)
	}
	// A second call while already reconnecting is a no-op.
	if m.beginReconnect(io.EOF) != nil {
		t.Fatal("second beginReconnect should be a no-op")
	}
}

func TestOnEventFsRefreshesCurrentDir(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.screen = screenCommander
	m.profile = Profile{Name: "vps"}
	left := newPanel(false, "/tmp", "/tmp")
	right := newPanel(true, "vps", "/incoming")
	right.SetEntries([]Entry{{Name: "a.txt"}}, true)
	m.panels = [2]*Panel{left, right}
	m.active = 1

	// A create in the shown directory triggers a keep-cursor refresh.
	cmd := m.onEvent(proto.EventFs{Op: proto.FsCreated, Kind: proto.KindFile, Path: "/incoming/new.txt", Size: 10})
	if cmd == nil {
		t.Fatal("event in current dir should return a refresh command")
	}
	if !m.busy || m.remoteKeepCursor < 0 {
		t.Fatalf("expected busy + keep-cursor set; busy=%v keep=%d", m.busy, m.remoteKeepCursor)
	}
	joined := strings.Join(logTexts(m.opLog), "\n")
	if !strings.Contains(joined, "appeared: /incoming/new.txt") {
		t.Fatalf("op log missing event line:\n%s", joined)
	}

	// A create elsewhere is logged but does not refresh.
	m.busy = false
	m.remoteKeepCursor = -1
	cmd = m.onEvent(proto.EventFs{Op: proto.FsCreated, Path: "/other/x", Size: 1})
	if cmd != nil || m.busy {
		t.Fatal("event outside the shown dir should not refresh")
	}
}

func logTexts(lines []logLine) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.text
	}
	return out
}
