package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// screen — какой из двух экранов сейчас показан: форма подключения или
// двухпанельный командер.
type screen int

const (
	screenConnect   screen = iota // экран логина (хост/порт/логин/пароль)
	screenCommander               // основной двухпанельный экран
)

const helpText = "Tab switch · ↑↓/PgUp/PgDn/Home/End move · Enter cd · Space mark · F5 download · Ctrl+R refresh · Ctrl+N mark seen · : command · F10 quit"

// transferState — состояние ТЕКУЩЕЙ (одной) идущей передачи: имя файла, сколько
// байт получено из скольки всего и когда началась (для расчёта скорости и ETA).
type transferState struct {
	name      FileName
	received  ByteSize
	total     ByteSize
	startedAt time.Time
}

// downloadJob — одна задача в очереди скачивания: откуда (сервер), куда (локально)
// и под каким именем. Очередь выполняется последовательно, по одной передаче.
type downloadJob struct {
	remote RemotePath
	local  LocalPath
	name   FileName
}

// Model — модель Bubble Tea для fshare-commander: ЕДИНОЕ состояние всего UI.
// Меняется только в Update (метод в model.go), рисуется только во View.
// Поля сгруппированы по назначению (экран подключения, командер, админ-панель,
// реконнект, командная строка). Сетевой клиент прячется за clientMu, потому что
// к нему обращаются и Update, и фоновый насос.
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
	connectGen    int // bumps per dial attempt; a result from a stale gen is ignored
	spinner       spinner.Model
	status        string
	connectErr    string

	// commander
	panels   [2]*Panel
	active   int
	opLog    []logLine
	prog     progress.Model
	transfer *transferState
	dlCancel context.CancelFunc // cancels the active download (Esc)
	queue    []downloadJob
	busy     bool
	link     linkState

	// admin panel (F9)
	admin        bool
	adminTab     int
	adminStats   proto.AdminStatsResponse
	adminClients []proto.ClientInfo
	adminConfig  []configKey
	adminCursor  int
	adminEditing bool
	adminInput   textinput.Model
	adminEditKey string
	adminMsg     string
	adminJournal []logLine // live tail of EVENT_NOTICE/EVENT_CONFIG (Journal tab)

	// admin confirmation modal (F2 shutdown / kick)
	adminConfirm      confirmKind
	adminConfirmArg   uint64            // e.g. session id for a kick confirm
	adminConfirmInput textinput.Model   // typed-word confirm (shutdown)
	adminDetail       *proto.ClientInfo // Enter on Clients tab: session detail box
	adminMenu         bool              // F2 lifecycle menu is open
	adminMenuCursor   int

	clientMu   sync.Mutex // serializes all client I/O across goroutines
	client     *client.Client
	profile    Profile
	serverName string
	role       proto.Role

	// состояние реконнекта
	host             Host
	port             Port
	password         string
	reconnecting     bool
	backoff          time.Duration // текущая задержка экспоненциального отката
	pumpStop         chan struct{} // закрытие останавливает фоновый насос
	remoteKeepCursor int           // >=0 восстанавливает курсор после живого обновления панели

	// command line (":" opens it)
	cmdMode  bool
	cmdInput textinput.Model

	// hotkey overlays
	fullLog         bool     // Ctrl+O: fullscreen op-log
	infoBox         []string // F3/F4: entry info/checksum box (nil = closed)
	dlCancelConfirm bool     // Esc during a transfer asks before cancelling

	events   chan tea.Msg
	quitting bool
}

// New создаёт стартовую модель на экране подключения, заранее заполняя поля из
// профиля prefill: непустое Name загружает сохранённый профиль; Host/Port/Login
// переопределяют форму. Здесь же готовятся текстовые поля, спиннер и канал events,
// через который в UI будут приходить асинхронные сообщения.
func New(prefill Profile) *Model {
	host := newThemedInput()
	host.Placeholder = "host"
	host.CharLimit = 255
	host.Width = 28
	host.Focus()

	port := newThemedInput()
	port.SetValue("5555")
	port.CharLimit = 5
	port.Width = 8

	login := newThemedInput()
	login.Placeholder = "login"
	login.Width = 20

	pw := newThemedInput()
	pw.Placeholder = "password"
	pw.EchoMode = textinput.EchoPassword
	pw.EchoCharacter = '•'
	pw.Width = 20

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = styAccent

	m := &Model{
		screen:           screenConnect,
		fields:           []textinput.Model{host, port, login, pw},
		profiles:         LoadProfiles(),
		prog:             progress.New(progress.WithGradient("#bb9af7", "#7dcfff")),
		spinner:          sp,
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

// Init реализует tea.Model: стартовая команда — waitForActivity, «слушатель»
// канала events, который превращает приходящие туда кадры в сообщения tea.Msg
// (без него сообщения из канала не дойдут). Мигание курсора (textinput.Blink)
// не запускается осознанно: тема использует статичный курсор (style.go).
func (m *Model) Init() tea.Cmd {
	return waitForActivity(m.events)
}

// Update реализует tea.Model: ЕДИНСТВЕННОЕ место, где меняется состояние модели.
// Разбирает очередное сообщение (клавиша, изменение размера, ответ сети, событие)
// и возвращает обновлённую модель и, возможно, команду на следующий побочный
// эффект. Сообщения из канала events требуют перевзвода слушателя (см. fromChannel).
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
		if msg.gen == m.connectGen { // ignore a stale/cancelled attempt's error
			m.connecting = false
			m.connectErr = msg.err.Error()
		}
	case spinner.TickMsg:
		if m.connecting {
			var c tea.Cmd
			m.spinner, c = m.spinner.Update(msg)
			cmd = c
		}
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
		m.dlCancel = nil
		m.refreshLocal(m.localIdx())
		cmd = m.afterRemoteOp()
	case downloadErrMsg:
		m.transfer = nil
		m.dlCancel = nil
		switch {
		case errors.Is(msg.err, context.Canceled):
			m.log(lineInfo, "download cancelled: "+msg.name)
			cmd = m.afterRemoteOp()
		case isConnLost(msg.err):
			cmd = m.beginReconnect(msg.err)
		default:
			m.log(lineErr, fmt.Sprintf("download %s failed: %v", msg.name, msg.err))
			cmd = m.afterRemoteOp()
		}
	case checksumMsg:
		var line string
		if msg.err != nil {
			line = "checksum error: " + msg.err.Error()
		} else {
			line = fmt.Sprintf("%s: %x", algoName(msg.algo), msg.sum[:])
		}
		m.log(lineInfo, msg.name+" "+line)
		if m.infoBox != nil {
			m.infoBox = append(m.infoBox, line)
		}
	case eventMsg:
		cmd = m.onEvent(msg.m)
	case connLostMsg:
		cmd = m.beginReconnect(msg.err)
	case reconnectedMsg:
		cmd = m.onReconnected(msg)
	case reconnectFailedMsg:
		cmd = m.onReconnectFailed(msg)
	case adminStatsMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminStats = msg.stats
		}
	case adminClientsMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminClients = msg.clients
			if m.adminCursor >= len(m.adminClients) {
				m.adminCursor = 0
			}
		}
	case adminConfigMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminConfig = msg.rows
		}
	case adminSetResultMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else if msg.ok {
			m.adminMsg = "applied: " + msg.key
			cmd = m.adminConfigCmd()
		} else {
			m.adminMsg = "rejected: " + msg.msg
		}
	case adminKickResultMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminMsg = msg.msg
			cmd = m.adminClientsCmd()
		}
	case adminReloadResultMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminMsg = "reload users: " + msg.msg
		}
	case adminShutdownResultMsg:
		if msg.err != nil {
			cmd = m.adminErr(msg.err)
		} else {
			m.adminMsg = "shutdown: " + msg.msg
		}
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
	if m.admin {
		return m.handleAdminKey(k)
	}
	if m.cmdMode {
		return m.handleCmdKey(k)
	}
	return m.handleCommanderKey(k)
}

// ---- connect screen ----

func (m *Model) profilesFocus() int { return len(m.fields) }

func (m *Model) hasProfiles() bool { return len(m.profiles.Profiles) > 0 }

func (m *Model) handleConnectKey(k tea.KeyMsg) tea.Cmd {
	// While a connect is in flight, only Esc (cancel) and Ctrl+C (quit) act.
	if m.connecting {
		switch k.String() {
		case "esc":
			m.connecting = false
			m.connectGen++ // invalidate the in-flight attempt; its late result is ignored
			m.status = ""
			m.connectErr = "connection cancelled"
			return nil
		case "ctrl+c", "f10":
			m.quitting = true
			return tea.Quit
		}
		return nil
	}
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
	m.connectGen++ // this dial's generation; late results from older gens are dropped
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
	return tea.Batch(dialCmd(addr, opts, prof, m.connectGen), m.spinner.Tick)
}

// ---- commander ----

func (m *Model) onConnected(msg connectedMsg) tea.Cmd {
	if msg.gen != m.connectGen {
		// A stale attempt (e.g. cancelled by Esc, or superseded by a newer dial):
		// drop the late connection instead of adopting it.
		msg.client.Close()
		return nil
	}
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

	// Remember the connection (host/login/name only — never the password).
	remembered := m.profile
	remembered.Secret = ""
	m.profiles.Upsert(remembered)
	_ = m.profiles.Save()

	m.subscribeFS()
	m.startPump()
	m.busy = true
	return m.listRemote("/")
}

func (m *Model) handleCommanderKey(k tea.KeyMsg) tea.Cmd {
	// An open info box (F3/F4) is dismissed by any key except Ctrl+C.
	if m.infoBox != nil {
		if k.String() == "ctrl+c" {
			return m.quit()
		}
		m.infoBox = nil
		return nil
	}
	// A pending "cancel download?" confirmation: 'y' confirms, anything else aborts.
	if m.dlCancelConfirm {
		m.dlCancelConfirm = false
		if k.String() == "y" && m.transfer != nil && m.dlCancel != nil {
			m.dlCancel()
			m.log(lineInfo, "cancelling "+m.transfer.name+"…")
		}
		return nil
	}
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
	case "*":
		m.activePanel().InvertSelect()
	case "f2":
		m.cyclePanelSort()
	case "f3":
		m.showEntryInfo()
	case "f4":
		return m.checksumEntry()
	case "ctrl+o":
		m.fullLog = !m.fullLog
	case "f5":
		return m.download()
	case "ctrl+r":
		return m.refreshActive()
	case "ctrl+n":
		m.activePanel().MarkAllSeen(time.Now().Unix())
		m.log(lineInfo, "marked all as seen")
	case "f9":
		return m.openAdmin()
	case "esc":
		if m.transfer != nil && m.dlCancel != nil {
			m.dlCancelConfirm = true // confirm before cancelling (spec §7)
		}
	case ":":
		m.enterCmdMode()
		return nil
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
		m.dlCancel = nil
		return
	}
	job := m.queue[0]
	m.queue = m.queue[1:]
	m.busy = true
	m.transfer = &transferState{name: job.name, startedAt: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	m.dlCancel = cancel
	m.log(lineInfo, "downloading "+job.name+"…")
	ev := m.events
	go func() {
		defer cancel() // release the context on any exit
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			ev <- downloadErrMsg{name: job.name, err: errClientClosed}
			return
		}
		var last uint64
		err := c.DownloadCtx(ctx, job.remote, job.local, func(p client.Progress) {
			last = p.Total
			// Non-blocking: never stall while holding clientMu even if the UI
			// loop is momentarily not draining (a dropped progress tick is
			// harmless; the next one or the done message corrects it).
			select {
			case ev <- progressMsg{name: job.name, received: p.Received, total: p.Total}:
			default:
			}
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
	// m.client is only ever assigned on this (Update) goroutine, so reading it
	// here is safe without clientMu — which matters because an in-flight
	// download goroutine holds clientMu for its whole transfer. Closing the
	// connection directly unblocks that download's read so it returns promptly.
	if m.client != nil {
		pr := m.profile
		pr.LastSeen = time.Now().Unix()
		m.profiles.Upsert(pr)
		_ = m.profiles.Save()
		m.client.Close()
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
