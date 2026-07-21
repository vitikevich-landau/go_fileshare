// Package tui implements the fileshare-commander interactive client as a Bubble
// Tea program. The state and navigation logic (Model/Panel) are kept free of
// terminal types so they can be unit-tested directly (docs/tz/09-go-port.md
// §5.9, docs/tz/04-tui-client.md §7).
package tui

import (
	"fmt"
	"sort"
)

// Entry is one row in a panel: a local or remote filesystem object.
type Entry struct {
	Name    string
	IsDir   bool
	Size    uint64
	Mtime   int64
	IsNew   bool // mtime later than the panel's last-seen snapshot
	HasPart bool // a matching .part exists (partial download)
	IsUp    bool // the synthetic ".." parent entry
}

// sortEntries orders directories before files, then by name.
func sortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].IsDir != es[j].IsDir {
			return es[i].IsDir
		}
		return es[i].Name < es[j].Name
	})
}

// formatSize renders a byte count in a compact human-readable form.
func formatSize(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
