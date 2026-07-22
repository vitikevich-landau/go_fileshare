package tui

import (
	"errors"
	"fmt"
	"path"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

var errClientClosed = errors.New("connection closed")

const (
	pollInterval  = 150 * time.Millisecond
	heartbeatEach = 20 * time.Second
	maxBackoff    = 30 * time.Second
)

// eventForwarder возвращает обработчик событий клиента, который НЕблокирующе
// переправляет асинхронные кадры в канал events модели (пропущенное событие лишь
// пропустит живое обновление; Ctrl+R восстановит). Неблокирующе — потому что
// нельзя тормозить сетевую горутину из-за занятого UI.
func (m *Model) eventForwarder() func(proto.Message) {
	ev := m.events
	return func(msg proto.Message) {
		select {
		case ev <- eventMsg{m: msg}:
		default:
		}
	}
}

// subscribeFS подписывается на события текущего клиента: события файловой системы
// — всем, плюс потоки config/notice для админов (для журнала админ-панели).
func (m *Model) subscribeFS() {
	mask := proto.SubFS
	if m.role == proto.RoleAdmin {
		mask |= proto.SubConfig | proto.SubNotice
	}
	m.clientMu.Lock()
	c := m.client
	if c != nil {
		_ = c.Subscribe(mask)
	}
	m.clientMu.Unlock()
}

// startPump запускает фоновую горутину-«насос»: в простое принимает события и
// шлёт heartbeat (docs/tz/04-tui-client.md §7). Это и есть работа сети ВНЕ
// UI-потока. Прежний насос сначала останавливается.
func (m *Model) startPump() {
	m.stopPump()
	stop := make(chan struct{})
	m.pumpStop = stop
	go m.runPump(stop)
}

func (m *Model) stopPump() {
	if m.pumpStop != nil {
		close(m.pumpStop)
		m.pumpStop = nil
	}
}

func (m *Model) runPump(stop chan struct{}) {
	lastPing := time.Now()
	for {
		select {
		case <-stop:
			return
		default:
		}

		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			time.Sleep(pollInterval)
			continue
		}
		_, err := c.PollEvents(pollInterval)
		if err == nil && time.Since(lastPing) > heartbeatEach {
			err = c.Ping()
			lastPing = time.Now()
		}
		m.clientMu.Unlock()

		if err != nil && isConnLost(err) {
			select {
			case m.events <- connLostMsg{err: err}:
			case <-stop:
			}
			return
		}
	}
}

// onEvent применяет асинхронный кадр: логирует и, если изменение произошло в
// показываемом сейчас удалённом каталоге, обновляет ту панель, сохраняя курсор.
func (m *Model) onEvent(pm proto.Message) tea.Cmd {
	switch e := pm.(type) {
	case proto.EventFs:
		verb := "changed"
		switch e.Op {
		case proto.FsCreated:
			verb = "appeared"
		case proto.FsRemoved:
			verb = "removed"
		}
		m.log(lineEvent, fmt.Sprintf("+ %s: %s (%s)", verb, e.Path, formatSize(e.Size)))
		rp := m.remotePanel()
		if rp != nil && path.Dir(e.Path) == rp.Path && !m.busy {
			m.remoteKeepCursor = rp.Cursor
			m.busy = true
			return m.listRemote(rp.Path)
		}
	case proto.EventNotice:
		m.log(lineInfo, "notice: "+e.Text)
		m.journal(lineEvent, "notice: "+e.Text)
	case proto.EventConfig:
		m.log(lineInfo, fmt.Sprintf("config: %s = %s", e.Key, e.NewValue))
		m.journal(lineInfo, fmt.Sprintf("config: %s = %s", e.Key, e.NewValue))
		m.onAdminConfigEvent(e) // live-update the settings tab if open
	}
	return nil
}

func (m *Model) remotePanel() *Panel {
	for i := range m.panels {
		if m.panels[i] != nil && m.panels[i].Remote {
			return m.panels[i]
		}
	}
	return nil
}

// beginReconnect сворачивает оборвавшееся соединение и планирует попытку
// реконнекта. Идемпотентна, пока реконнект уже идёт.
func (m *Model) beginReconnect(cause error) tea.Cmd {
	// Игнорируем запоздавшее событие потери связи от сессии, которую мы уже
	// покинули (например, после явного `disconnect`): иначе устаревший
	// connLostMsg/remoteErrMsg молча превратил бы disconnect обратно в фоновый реконнект.
	if m.screen != screenCommander {
		return nil
	}
	if m.reconnecting {
		return nil
	}
	m.reconnecting = true
	m.link = linkReconnect
	m.stopPump()
	m.clientMu.Lock()
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	m.clientMu.Unlock()
	m.busy = false
	m.transfer = nil
	m.queue = nil
	m.backoff = time.Second
	m.log(lineErr, fmt.Sprintf("connection lost (%v) — reconnecting…", cause))
	return m.reconnectCmd()
}

func (m *Model) reconnectCmd() tea.Cmd {
	delay := m.backoff
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	opts := client.Options{
		Login:        m.profile.Login,
		Password:     m.password,
		ClientName:   "fshare-commander",
		EventHandler: m.eventForwarder(),
	}
	return func() tea.Msg {
		time.Sleep(delay)
		c, err := client.Dial(addr, opts)
		if err != nil {
			return reconnectFailedMsg{err: err}
		}
		return reconnectedMsg{client: c}
	}
}

// onReconnected принимает успешно переподключённый клиент: заменяет им старый,
// возобновляет подписки и насос и перечитывает показываемый удалённый каталог.
func (m *Model) onReconnected(msg reconnectedMsg) tea.Cmd {
	if !m.reconnecting || m.screen != screenCommander {
		// Мы отключились (или сбросились), пока этот реконнект был в полёте: роняем
		// запоздавшее соединение, а не принимаем его незаметно.
		if msg.client != nil {
			msg.client.Close()
		}
		return nil
	}
	m.clientMu.Lock()
	m.client = msg.client
	m.clientMu.Unlock()
	m.reconnecting = false
	m.link = linkUp
	m.backoff = time.Second
	m.role = msg.client.Role()
	m.log(lineOK, "reconnected")
	m.subscribeFS()
	m.startPump()

	// Re-read the currently shown remote directory.
	rp := m.remotePanel()
	if rp != nil {
		m.remoteKeepCursor = rp.Cursor
		m.busy = true
		return m.listRemote(rp.Path)
	}
	return nil
}

// onReconnectFailed обрабатывает неудачную попытку: удваивает задержку отката (до
// maxBackoff) и планирует следующую попытку — экспоненциальный backoff.
func (m *Model) onReconnectFailed(msg reconnectFailedMsg) tea.Cmd {
	if !m.reconnecting {
		return nil // тем временем отключились: перестаём пытаться
	}
	m.backoff *= 2
	if m.backoff > maxBackoff {
		m.backoff = maxBackoff
	}
	m.log(lineErr, fmt.Sprintf("reconnect failed (%v); retrying in %s", msg.err, m.backoff))
	return m.reconnectCmd()
}
