package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// linkState — индикатор состояния связи (цветной значок в статусе).
type linkState int

const (
	linkDown      linkState = iota // нет связи
	linkReconnect                  // идёт переподключение
	linkUp                         // связь есть
)

// lineKind — вид строки лога операций (задаёт цвет).
type lineKind int

const (
	lineInfo  lineKind = iota // обычная информация
	lineOK                    // успех (зелёная)
	lineErr                   // ошибка (красная)
	lineEvent                 // push-событие от сервера
)

// logLine — одна строка лога операций: текст плюс его вид.
type logLine struct {
	text string
	kind lineKind
}

// ---- асинхронные сообщения (tea.Msg) ----
//
// Это результаты побочных эффектов (сетевых запросов, скачивания, событий),
// которые приходят обратно в Update как сообщения. Часть приходит из tea.Cmd,
// часть — из канала events (см. fromChannel ниже).

type connectedMsg struct {
	client     *client.Client
	serverName string
	motd       string
	role       proto.Role
	profile    Profile
	gen        int // the dial attempt this result belongs to
}

type connectErrMsg struct {
	err error
	gen int
}

type remoteListingMsg struct {
	path    string
	entries []proto.DirEntry
}

type remoteErrMsg struct{ err error }

// Следующие сообщения текут через канал events модели из горутины скачивания
// (docs/tz/09-go-port.md §5.9) — так прогресс попадает в UI, не блокируя сеть.
type progressMsg struct {
	name     string
	received uint64
	total    uint64
}

type downloadDoneMsg struct {
	name  string
	bytes uint64
}

type downloadErrMsg struct {
	name string
	err  error
}

// checksumMsg carries the result of an F4 checksum request.
type checksumMsg struct {
	name string
	algo proto.Algo
	sum  [proto.ChecksumLen]byte
	err  error
}

// eventMsg carries an async EVENT_*/PONG frame from the connection pump.
type eventMsg struct{ m proto.Message }

// connLostMsg is posted by the pump when the connection drops.
type connLostMsg struct{ err error }

// reconnectedMsg / reconnectFailedMsg are results of a reconnect attempt (Cmd,
// not channel-sourced).
type reconnectedMsg struct{ client *client.Client }
type reconnectFailedMsg struct{ err error }

// fromChannel сообщает, пришло ли сообщение через канал events и, значит, требует
// перевзвода слушателя (иначе следующее сообщение из канала не будет прочитано).
func fromChannel(msg tea.Msg) bool {
	switch msg.(type) {
	case progressMsg, downloadDoneMsg, downloadErrMsg, eventMsg, connLostMsg, checksumMsg:
		return true
	}
	return false
}
