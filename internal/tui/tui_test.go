package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFormatSize(t *testing.T) {
	cases := map[uint64]string{
		0:                      "0B",
		5:                      "5B",
		1023:                   "1023B",
		1024:                   "1.0K",
		1536:                   "1.5K",
		1024 * 1024:            "1.0M",
		3 * 1024 * 1024 * 1024: "3.0G",
	}
	for in, want := range cases {
		if got := formatSize(in); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestPanelSetEntriesSortsAndFlags(t *testing.T) {
	p := newPanel(true, "remote", "/sub")
	p.LastSeen = 100
	p.SetEntries([]Entry{
		{Name: "b.txt", Mtime: 150},
		{Name: "a.txt", Mtime: 50},
		{Name: "zdir", IsDir: true, Mtime: 200},
	}, true)

	wantOrder := []string{"..", "zdir", "a.txt", "b.txt"}
	if len(p.Entries) != len(wantOrder) {
		t.Fatalf("entries = %d, want %d", len(p.Entries), len(wantOrder))
	}
	for i, w := range wantOrder {
		if p.Entries[i].Name != w {
			t.Fatalf("order[%d] = %q, want %q", i, p.Entries[i].Name, w)
		}
	}
	if !p.Entries[0].IsUp {
		t.Error("first entry should be the .. parent")
	}
	// new: b.txt (150) and zdir (200) are past last_seen 100; a.txt (50) is not.
	if p.NewCount() != 2 {
		t.Errorf("NewCount = %d, want 2", p.NewCount())
	}
	if p.FileCount() != 2 {
		t.Errorf("FileCount = %d, want 2", p.FileCount())
	}
}

func TestPanelNavigationClamps(t *testing.T) {
	p := newPanel(false, "l", "/")
	entries := make([]Entry, 10)
	for i := range entries {
		entries[i] = Entry{Name: string(rune('a' + i))}
	}
	p.SetEntries(entries, false)

	p.Move(-5, 4) // clamp at top
	if p.Cursor != 0 {
		t.Fatalf("cursor = %d, want 0", p.Cursor)
	}
	p.Move(100, 4) // clamp at bottom
	if p.Cursor != 9 {
		t.Fatalf("cursor = %d, want 9", p.Cursor)
	}
	// bottom must be visible within a 4-row viewport
	if p.Cursor < p.Top || p.Cursor >= p.Top+4 {
		t.Fatalf("cursor %d not visible in viewport [%d,%d)", p.Cursor, p.Top, p.Top+4)
	}
}

func TestPanelSelectAndTargets(t *testing.T) {
	p := newPanel(true, "r", "/")
	p.SetEntries([]Entry{
		{Name: "dir", IsDir: true},
		{Name: "one.txt"},
		{Name: "two.txt"},
	}, false)

	// Cursor on the directory: no file target.
	p.Cursor = 0
	if len(p.Targets()) != 0 {
		t.Fatal("directory should not be a download target")
	}
	// Cursor on a file: that file is the target.
	p.Cursor = 1
	tg := p.Targets()
	if len(tg) != 1 || tg[0].Name != "one.txt" {
		t.Fatalf("current-file target = %v", tg)
	}
	// Selection overrides the cursor.
	p.Selected["two.txt"] = true
	tg = p.Targets()
	if len(tg) != 1 || tg[0].Name != "two.txt" {
		t.Fatalf("selected target = %v", tg)
	}
}

func TestProfilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir) // Windows path

	p := LoadProfiles()
	if len(p.Profiles) != 0 {
		t.Fatal("fresh profiles should be empty")
	}
	p.Upsert(Profile{Name: "vps", Host: "h", Port: 5555, Login: "vit", LastSeen: 42})
	p.Upsert(Profile{Name: "vps", Host: "h2", Port: 6000, Login: "vit"}) // replace
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := filepath.Abs(profilesPath()); err != nil {
		t.Fatal(err)
	}

	p2 := LoadProfiles()
	pr, ok := p2.Find("vps")
	if !ok || pr.Host != "h2" || pr.Port != 6000 {
		t.Fatalf("reloaded profile = %+v ok=%v", pr, ok)
	}
	if len(p2.Profiles) != 1 {
		t.Fatalf("expected 1 profile after upsert-replace, got %d", len(p2.Profiles))
	}
}

func TestConnectValidation(t *testing.T) {
	m := New(Profile{})
	m.fields[0].SetValue("") // empty host
	if cmd := m.doConnect(); cmd != nil || m.connectErr == "" {
		t.Fatal("empty host should set connectErr and return no command")
	}
	m.fields[0].SetValue("host")
	m.fields[1].SetValue("99999") // out of range
	if cmd := m.doConnect(); cmd != nil || m.connectErr == "" {
		t.Fatal("bad port should set connectErr and return no command")
	}
	m.fields[1].SetValue("5555")
	if cmd := m.doConnect(); cmd == nil {
		t.Fatal("valid inputs should return a dial command")
	}
}

func TestHeadlessCommanderRender(t *testing.T) {
	m := New(Profile{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	// Drive into the commander screen with two populated panels.
	m.screen = screenCommander
	m.serverName = "test"
	m.profile = Profile{Login: "vit"}
	left := newPanel(false, "/home/vit", "/home/vit")
	left.SetEntries([]Entry{{Name: "report.pdf", Size: 1200}}, true)
	right := newPanel(true, "vps:/", "/")
	right.SetEntries([]Entry{
		{Name: "video", IsDir: true},
		{Name: "big.bin", Size: 300000, Mtime: 1_000_000},
	}, false)
	m.panels = [2]*Panel{left, right}
	m.active = 1
	m.link = linkUp
	m.log(lineOK, "connected to test")

	out := m.View()
	if out == "" {
		t.Fatal("commander view rendered empty")
	}
	for _, want := range []string{"big.bin", "video", "report.pdf", "vit@test", "Quit"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered view missing %q", want)
		}
	}
}

func TestHeadlessConnectRender(t *testing.T) {
	m := New(Profile{Host: "vps.example.com", Port: 5555, Login: "vit"})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	out := m.View()
	if !strings.Contains(out, "fileshare commander") || !strings.Contains(out, "Host:") {
		t.Fatalf("connect view missing expected content:\n%s", out)
	}
}
