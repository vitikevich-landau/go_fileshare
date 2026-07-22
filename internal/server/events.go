package server

import (
	"context"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/watcher"
)

// startWatcher запускает файловый watcher (если события включены), привязанный к
// ctx, чтобы изменения под корнем раздачи рассылались как EVENT_FS. Если watcher
// не удалось создать, сервер работает дальше без push-событий.
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

// handleFsEvent сбрасывает checksum-кэш для изменившегося пути и рассылает
// EVENT_FS подписчикам (docs/tz/09-go-port.md §5.7). Сброс кэша обязателен: иначе
// после изменения файла клиент получил бы устаревшую сумму.
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

// BroadcastNotice рассылает EVENT_NOTICE подписчикам серверных уведомлений
// (например, о смене настройки, kick-е или скорой остановке).
func (s *Server) BroadcastNotice(sev proto.Severity, text string) {
	frame := proto.Encode(proto.EventNotice{Severity: sev, Text: text})
	s.reg.broadcast(proto.SubNotice, frame)
}
