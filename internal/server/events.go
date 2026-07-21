package server

import (
	"context"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/watcher"
)

// startWatcher launches the filesystem watcher (if events are enabled) bound to
// ctx, so changes under the share root are broadcast as EVENT_FS.
func (s *Server) startWatcher(ctx context.Context) {
	cur := s.hub.Current()
	if !cur.Events.Enabled {
		return
	}
	debounce := time.Duration(cur.Events.DebounceMs) * time.Millisecond
	w, err := watcher.New(s.vfs.RootName(), debounce, s.handleFsEvent)
	if err != nil {
		s.log.Error("filesystem watcher disabled", "err", err)
		return
	}
	w.Start(ctx)
	s.log.Info("filesystem watcher started", "debounce_ms", cur.Events.DebounceMs)
}

// handleFsEvent invalidates the checksum cache for the changed path and
// broadcasts an EVENT_FS to subscribers (docs/tz/09-go-port.md §5.7).
func (s *Server) handleFsEvent(ev watcher.Event) {
	s.vfs.InvalidateChecksum(ev.VPath)
	frame := proto.Encode(proto.EventFs{
		Op:    ev.Op,
		Kind:  ev.Kind,
		Path:  ev.VPath,
		Size:  ev.Size,
		Mtime: ev.Mtime,
	})
	s.reg.broadcast(proto.SubFS, frame)
}

// BroadcastNotice sends an EVENT_NOTICE to subscribers of server notices.
func (s *Server) BroadcastNotice(sev proto.Severity, text string) {
	frame := proto.Encode(proto.EventNotice{Severity: sev, Text: text})
	s.reg.broadcast(proto.SubNotice, frame)
}
