package tui

import (
	"fmt"
	"path"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// cyclePanelSort advances the active panel's sort order (F2) and re-sorts it.
func (m *Model) cyclePanelSort() {
	p := m.activePanel()
	p.Sort = (p.Sort + 1) % sortModeCount
	p.Resort()
	m.log(lineInfo, "sort by "+p.Sort.String())
}

// showEntryInfo opens the info box for the cursor entry (F3): quick properties,
// no network round-trip.
func (m *Model) showEntryInfo() {
	e, ok := m.activePanel().Current()
	if !ok || e.IsUp {
		return
	}
	kind := "file"
	if e.IsDir {
		kind = "dir"
	}
	when := ""
	if e.Mtime > 0 {
		when = time.Unix(e.Mtime, 0).Format("2006-01-02 15:04:05")
	}
	m.infoBox = []string{
		"Name: " + e.Name,
		"Type: " + kind,
		"Size: " + formatSize(e.Size),
		"Date: " + when,
	}
}

// checksumEntry opens the info box and fetches the remote file's checksum (F4).
func (m *Model) checksumEntry() tea.Cmd {
	p := m.activePanel()
	if !p.Remote {
		m.log(lineErr, "checksum: remote files only")
		return nil
	}
	e, ok := p.Current()
	if !ok || e.IsDir || e.IsUp {
		m.log(lineInfo, "checksum: move the cursor onto a file")
		return nil
	}
	m.infoBox = []string{
		"Name: " + e.Name,
		"Size: " + formatSize(e.Size),
		"Checksum: computing…",
	}
	remote := path.Join(p.Path, e.Name)
	name := e.Name
	ev := m.events
	return func() tea.Msg {
		m.clientMu.Lock()
		c := m.client
		if c == nil {
			m.clientMu.Unlock()
			return checksumMsg{name: name, err: errClientClosed}
		}
		algo, sum, err := c.Checksum(remote)
		m.clientMu.Unlock()
		ev <- checksumMsg{name: name, algo: algo, sum: sum, err: err}
		return nil
	}
}

// algoName renders a checksum algorithm id.
func algoName(a proto.Algo) string {
	switch a {
	case proto.AlgoSHA256:
		return "sha256"
	case proto.AlgoCRC32:
		return "crc32"
	default:
		return fmt.Sprintf("algo#%d", a)
	}
}
