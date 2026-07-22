package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// linkState is the connection indicator.
type linkState int

const (
	linkDown linkState = iota
	linkReconnect
	linkUp
)

type lineKind int

const (
	lineInfo lineKind = iota
	lineOK
	lineErr
	lineEvent
)

type logLine struct {
	text string
	kind lineKind
}

// ---- async messages ----

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

// The following flow through the model's events channel from the download
// goroutine (docs/tz/09-go-port.md §5.9).
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

// fromChannel reports whether a message arrives via the events channel and thus
// requires re-arming the listener.
func fromChannel(msg tea.Msg) bool {
	switch msg.(type) {
	case progressMsg, downloadDoneMsg, downloadErrMsg, eventMsg, connLostMsg, checksumMsg:
		return true
	}
	return false
}
