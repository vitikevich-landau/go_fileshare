package tui

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

type screen int

const (
	screenConnect screen = iota
	screenCommander
)

const helpText = "Tab switch · ↑↓/PgUp/PgDn/Home/End move · Enter cd · Space mark · F5 download · Ctrl+R refresh · Ctrl+N mark seen · F10 quit"

type transferState struct {
	name     string
	received uint64
	total    uint64
}

type downloadJob struct {
	remote string
	local  string
	name   string
}

// Model is the Bubble Tea model for fshare-commander.
type Model struct {
	screen        screen
	width, height int
	panelRows     int

	// connect screen
	fields        []textinput.Model // host, port, login, password
	focus         int
	profiles      *Profiles
	profileCursor int
	connecting    bool
	status        string
	connectErr    string

	// commander
	panels   [2]*Panel
	active   int
	opLog    []logLine
	prog     progress.Model
	transfer *transferState
	queue    []downloadJob
	busy     bool
	link     linkState

	clientMu   sync.Mutex // serializes all client I/O across goroutines
	client     *client.Client
	profile    Profile
	serverName string
	role       proto.Role

	// reconnect state
	host             string
	port             int
	password         string
	reconnecting     bool
	backoff          time.Duration
	pumpStop         chan struct{}
	remoteKeepCursor int // >=0 restores the cursor after a live remote refresh

	events   chan tea.Msg
	quitting bool
}

// New builds the initial model. Fields of prefill seed the connect form: a
// non-empty Name loads that saved profile; Host/Port/Login override the form.
func New(prefill Profile) *Model {
	host := textinput.New()
	host.Placeholder = "host"
	host.CharLimit = 255
	host.Width = 28
	host.Focus()

	port := textinput.New()
	port.SetValue("5555")
	port.CharLimit = 5
	port.Width = 8

	login := textinput.New()
	login.Placeholder = "login"
	login.Width = 20

	pw := textinput.New()
	pw.Placeholder = "password"
	pw.EchoMode = textinput.EchoPassword
	pw.EchoCharacter = '*'
	pw.Width = 20

	m := &Model{
		screen:           screenConnect,
		fields:           []textinput.Model{host, port, login, pw},
		profiles:         LoadProfiles(),
		prog:             progress.New(progress.WithDefaultGradient()),
		events:           make(chan tea.Msg, 64),
		link:             linkDown,
		backoff:          time.Second,
		remoteKeepCursor: -1,
	}
	if prefill.Name != "" {
		if pr, ok := m.profiles.Find(prefill.Name); ok {
			m.loadProfile(pr)
		} else {
			m.profile.Name = prefill.Name
		}
	}
	if prefill.Host != "" {
		m.fields[0].SetValue(prefill.Host)
		m.profile.Host = prefill.Host
	}
	if prefill.Port != 0 {
		m.fields[1].SetValue(strconv.Itoa(prefill.Port))
		m.profile.Port = prefill.Port
	}
	if prefill.Login != "" {
		m.fields[2].SetValue(prefill.Login)
		m.profile.Login = prefill.Login
	}
	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, waitForActivity(m.events))
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.panelRows = m.height - 11
		if m.panelRows < 3 {
			m.panelRows = 3
		}
		m.prog.Width = m.width - 24
		if m.prog.Width < 10 {
			m.prog.Width = 10
		}
	case tea.KeyMsg:
		cmd = m.handleKey(msg)
	case connectedMsg:
		cmd = m.onConnected(msg)
	case connectErrMsg:
		m.connecting = false
		m.connectErr = msg.err.Error()
	case remoteListingMsg:
		m.onRemoteListing(msg)
		cmd = m.afterRemoteOp()
	case remoteErrMsg:
		if isConnLost(msg.err) {
			cmd = m.beginReconnect(msg.err)
		} else {
			m.log(lineErr, "remote: "+msg.err.Error())
			cmd = m.afterRemoteOp()
		}
	case progressMsg:
		if m.transfer != nil && m.transfer.name == msg.name {
			m.transfer.received, m.transfer.total = msg.received, msg.total
		}
	case downloadDoneMsg:
		m.log(lineOK, fmt.Sprintf("downloaded %s (%s)", msg.name, formatSize(msg.bytes)))
		m.transfer = nil
		m.refreshLocal(m.localIdx())
		cmd = m.afterRemoteOp()
	case downloadErrMsg:
		m.transfer = nil
		if isConnLost(msg.err) {
			cmd = m.beginReconnect(msg.err)
		} else {
			m.log(lineErr, fmt.Sprintf("download %s failed: %v", msg.name, msg.err))
			cmd = m.afterRemoteOp()
		}
	case eventMsg:
		cmd = m.onEvent(msg.m)
	case connLostMsg:
		cmd = m.beginReconnect(msg.err)
	case reconnectedMsg:
		cmd = m.onReconnected(msg)
	case reconnectFailedMsg:
		cmd = m.onReconnectFailed(msg)
	}

	if fromChannel(msg) {
		cmd = tea.Batch(cmd, waitForActivity(m.events))
	}
	return m, cmd
}

func (m *Model) handleKey(k tea.KeyMsg) tea.Cmd {
	if m.screen == screenConnect {
		return m.handleConnectKey(k)
	}
	return m.handleCommanderKey(k)
}

// ---- connect screen ----

func (m *Model) profilesFocus() int { return len(m.fields) }

func (m *Model) hasProfiles() bool { return len(m.profiles.Profiles) > 0 }

func (m *Model) handleConnectKey(k tea.KeyMsg) tea.Cmd {
	switch k.String() {
	case "ctrl+c", "f10", "esc":
		m.quitting = true
		return tea.Quit
	case "tab":
		m.focusDelta(1)
		return nil
	case "shift+tab":
		m.focusDelta(-1)
		return nil
	case "up":
		if m.focus == m.profilesFocus() {
			if m.profileCursor > 0 {
				m.profileCursor--
			}
		} else {
			m.focusDelta(-1)
		}
		return nil
	case "down":
		if m.focus == m.profilesFocus() {
			if m.profileCursor < len(m.profiles.Profiles)-1 {
				m.profileCursor++
			}
		} else {
			m.focusDelta(1)
		}
		return nil
	case "enter":
		return m.onConnectEnter()
	}
	if m.focus < len(m.fields) {
		var c tea.Cmd
		m.fields[m.focus], c = m.fields[m.focus].Update(k)
		return c
	}
	return nil
}

func (m *Model) focusDelta(d int) {
	n := len(m.fields)
	if m.hasProfiles() {
		n++
	}
	m.focus = ((m.focus+d)%n + n) % n
	for i := range m.fields {
		if i == m.focus {
			m.fields[i].Focus()
		} else {
			m.fields[i].Blur()
		}
	}
}

func (m *Model) onConnectEnter() tea.Cmd {
	if m.focus == m.profilesFocus() && m.hasProfiles() {
		pr := m.profiles.Profiles[m.profileCursor]
		m.loadProfile(pr)
	}
	return m.doConnect()
}

func (m *Model) loadProfile(pr Profile) {
	m.fields[0].SetValue(pr.Host)
	m.fields[1].SetValue(strconv.Itoa(pr.Port))
	m.fields[2].SetValue(pr.Login)
	m.profile = pr
}

func (m *Model) doConnect() tea.Cmd {
	host := strings.TrimSpace(m.fields[0].Value())
	portStr := strings.TrimSpace(m.fields[1].Value())
	login := strings.TrimSpace(m.fields[2].Value())
	pw := m.fields[3].Value()

	if host == "" {
		m.connectErr = "host is required"
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		m.connectErr = "invalid port"
		return nil
	}
	m.connectErr = ""
	m.connecting = true
	m.status = "connecting to " + host + "…"

	name := m.profile.Name
	if name == "" {
		name = host
	}
	// Remember connection details for auto-reconnect.
	m.host, m.port, m.password = host, port, pw

	prof := Profile{Name: name, Host: host, Port: port, Login: login, LastSeen: m.profile.LastSeen, DownloadsDir: m.profile.DownloadsDir}
	addr := fmt.Sprintf("%s:%d", host, port)
	opts := client.Options{Login: login, Password: pw, ClientName: "fshare-commander", EventHandler: m.eventForwarder()}
	return dialCmd(addr, opts, prof)
}

// ---- commander ----

func (m *Model) onConnected(msg connectedMsg) tea.Cmd {
	m.client = msg.client
	m.role = msg.role
	m.serverName = msg.serverName
	m.profile = msg.profile
	m.connecting = false
	m.link = linkUp
	m.screen = screenCommander

	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	left := newPanel(false, wd, wd)
	right := newPanel(true, m.profile.Name, "/")
	right.LastSeen = m.profile.LastSeen
	m.panels = [2]*Panel{left, right}
	m.active = 1 // remote panel active by default so F5 works immediately

	m.cdLocal(0, wd)
	if msg.motd != "" {
		m.log(lineInfo, "motd: "+msg.motd)
	}
	m.log(lineOK, "connected to "+m.serverName+" as "+m.role.String())

	m.subscribeFS()
	m.startPump()
	m.busy = true
	return m.listRemote("/")
}

func (m *Model) handleCommanderKey(k tea.KeyMsg) tea.Cmd {
	switch k.String() {
	case "ctrl+c":
		return m.quit()
	case "f10", "q":
		if m.transfer != nil || len(m.queue) > 0 {
			m.log(lineInfo, "transfer in progress — press Ctrl+C to force quit")
			return nil
		}
		return m.quit()
	case "tab":
		m.active = 1 - m.active
	case "up":
		m.activePanel().Move(-1, m.panelRows)
	case "down":
		m.activePanel().Move(1, m.panelRows)
	case "pgup":
		m.activePanel().Move(-(m.panelRows - 1), m.panelRows)
	case "pgdown":
		m.activePanel().Move(m.panelRows-1, m.panelRows)
	case "home":
		m.activePanel().MoveTo(0, m.panelRows)
	case "end":
		m.activePanel().MoveTo(len(m.activePanel().Entries)-1, m.panelRows)
	case "enter":
		return m.enter()
	case " ", "insert":
		m.activePanel().ToggleSelect()
		m.activePanel().Move(1, m.panelRows)
	case "f5":
		return m.download()
	case "ctrl+r":
		return m.refreshActive()
	case "ctrl+n":
		m.activePanel().MarkAllSeen(time.Now().Unix())
		m.log(lineInfo, "marked all as seen")
	case "f1":
		m.log(lineInfo, helpText)
	}
	return nil
}

func (m *Model) activePanel() *Panel { return m.panels[m.active] }

func (m *Model) localIdx() int {
	if m.panels[0].Remote {
		return 1
	}
	return 0
}

func (m *Model) enter() tea.Cmd {
	p := m.activePanel()
	e, ok := p.Current()
	if !ok {
		return nil
	}
	if e.IsUp {
		if p.Remote {
			return m.cdRemote(path.Dir(p.Path))
		}
		m.cdLocal(m.active, filepath.Dir(p.Path))
		return nil
	}
	if e.IsDir {
		if p.Remote {
			return m.cdRemote(path.Join(p.Path, e.Name))
		}
		m.cdLocal(m.active, filepath.Join(p.Path, e.Name))
		return nil
	}
	return nil // file: use F5 to download
}

func (m *Model) cdRemote(newPath string) tea.Cmd {
	if m.busy {
		m.log(lineInfo, "busy — please wait")
		return nil
	}
	m.busy = true
	return m.listRemote(newPath)
}

func (m *Model) cdLocal(idx int, dir string) {
	entries, abs, hasParent, err := readLocalDir(dir)
	if err != nil {
		m.log(lineErr, "local: "+err.Error())
		return
	}
	p := m.panels[idx]
	p.Path = abs
	p.Label = abs
	p.Cursor, p.Top = 0, 0
	p.SetEntries(entries, hasParent)
}

func (m *Model) refreshLocal(idx int) {
	p := m.panels[idx]
	entries, abs, hasParent, err := readLocalDir(p.Path)
	if err != nil {
		m.log(lineErr, "local: "+err.Error())
		return
	}
	cur := p.Cursor
	p.Path = abs
	p.SetEntries(entries, hasParent)
	p.MoveTo(cur, m.panelRows)
}

func (m *Model) refreshActive() tea.Cmd {
	p := m.activePanel()
	if p.Remote {
		return m.cdRemote(p.Path)
	}
	m.refreshLocal(m.active)
	return nil
}

func (m *Model) onRemoteListing(msg remoteListingMsg) {
	p := m.panels[1]
	if !p.Remote {
		p = m.panels[0]
	}
	p.Path = msg.path
	p.Label = m.profile.Name + ":" + msg.path
	keep := m.remoteKeepCursor
	m.remoteKeepCursor = -1
	if keep < 0 {
		p.Cursor, p.Top = 0, 0
	}
	p.SetEntries(toEntries(msg.entries), msg.path != "/")
	if keep >= 0 {
		p.MoveTo(keep, m.panelRows) // preserve cursor across a live refresh
	}
}

func (m *Model) afterRemoteOp() tea.Cmd {
	m.busy = false
	m.startNext()
	return nil
}

func (m *Model) download() tea.Cmd {
	p := m.activePanel()
	if !p.Remote {
		m.log(lineErr, "upload from local is not supported yet (M13)")
		return nil
	}
	other := m.panels[1-m.active]
	if other.Remote {
		m.log(lineErr, "no local destination panel")
		return nil
	}
	targets := p.Targets()
	if len(targets) == 0 {
		m.log(lineInfo, "select a file (Space) or move the cursor onto one")
		return nil
	}
	for _, t := range targets {
		m.queue = append(m.queue, downloadJob{
			remote: path.Join(p.Path, t.Name),
			local:  filepath.Join(other.Path, t.Name),
			name:   t.Name,
		})
	}
	p.Selected = map[string]bool{}
	if !m.busy {
		m.startNext()
	}
	return nil
}

func (m *Model) startNext() {
	if len(m.queue) == 0 {
		m.busy = false
		m.transfer = nil
		return
	}
	job := m.queue[0]
	m.queue = m.queue[1:]
	m.busy = true
	m.transfer = &transferState{name: job.name}
	m.log(lineInfo, "downloading "+job.name+"…")
	ev := m.events
	go func() {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			ev <- downloadErrMsg{name: job.name, err: errClientClosed}
			return
		}
		var last uint64
		err := c.Download(job.remote, job.local, func(p client.Progress) {
			last = p.Total
			ev <- progressMsg{name: job.name, received: p.Received, total: p.Total}
		})
		m.clientMu.Unlock()
		if err != nil {
			ev <- downloadErrMsg{name: job.name, err: err}
			return
		}
		ev <- downloadDoneMsg{name: job.name, bytes: last}
	}()
}

func (m *Model) quit() tea.Cmd {
	m.stopPump()
	if m.client != nil {
		pr := m.profile
		pr.LastSeen = time.Now().Unix()
		m.profiles.Upsert(pr)
		_ = m.profiles.Save()
		m.clientMu.Lock()
		m.client.Close()
		m.clientMu.Unlock()
	}
	m.quitting = true
	return tea.Quit
}

func (m *Model) log(kind lineKind, text string) {
	m.opLog = append(m.opLog, logLine{text: text, kind: kind})
	if len(m.opLog) > 200 {
		m.opLog = m.opLog[len(m.opLog)-200:]
	}
}

func toEntries(des []proto.DirEntry) []Entry {
	out := make([]Entry, 0, len(des))
	for _, d := range des {
		out = append(out, Entry{
			Name:  d.Name,
			IsDir: d.Kind == proto.KindDir,
			Size:  d.Size,
			Mtime: int64(d.Mtime),
		})
	}
	return out
}
