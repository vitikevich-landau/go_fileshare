// Package watcher turns filesystem changes under the share root into debounced
// protocol events. It wraps fsnotify (cross-platform) and adds the recursive
// watching and debouncing the C++ reference did by hand
// (docs/tz/09-go-port.md §5.7).
package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// Event is a debounced change under the root, expressed with a virtual path.
type Event struct {
	Op    proto.FsOp
	Kind  proto.Kind
	VPath string
	Size  uint64
	Mtime uint64
}

// Watcher observes the share root recursively and calls onEvent for each
// debounced change.
type Watcher struct {
	root     string
	debounce time.Duration
	onEvent  func(Event)

	fsw *fsnotify.Watcher

	mu      sync.Mutex
	pending map[string]*pending // keyed by real path
}

type pending struct {
	timer   *time.Timer
	created bool
}

// New creates a watcher rooted at root. It does not start observing until Start.
func New(root string, debounce time.Duration, onEvent func(Event)) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		fsw.Close()
		return nil, err
	}
	w := &Watcher{
		root:     abs,
		debounce: debounce,
		onEvent:  onEvent,
		fsw:      fsw,
		pending:  map[string]*pending{},
	}
	if err := w.addRecursive(abs); err != nil {
		fsw.Close()
		return nil, err
	}
	return w, nil
}

// Start runs the event loop until ctx is cancelled, then closes the watcher.
func (w *Watcher) Start(ctx context.Context) {
	go func() {
		defer w.fsw.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.fsw.Events:
				if !ok {
					return
				}
				w.handle(ev)
			case _, ok := <-w.fsw.Errors:
				if !ok {
					return
				}
			}
		}
	}()
}

// removeWatchTree drops the watch on dir and on every still-registered
// descendant directory, so removing/renaming a non-empty subtree does not leak
// the per-subdir watches that addRecursive created.
func (w *Watcher) removeWatchTree(dir string) {
	_ = w.fsw.Remove(dir)
	prefix := dir + string(os.PathSeparator)
	for _, p := range w.fsw.WatchList() {
		if strings.HasPrefix(p, prefix) {
			_ = w.fsw.Remove(p)
		}
	}
}

// addRecursive registers dir and all of its subdirectories.
func (w *Watcher) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			_ = w.fsw.Add(path)
		}
		return nil
	})
}

func (w *Watcher) handle(ev fsnotify.Event) {
	// A newly created directory must be watched too (fsnotify is not recursive),
	// including any children created before we added it.
	if ev.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			_ = w.addRecursive(ev.Name)
		}
	}

	// A removed or renamed-away path may have been a watched directory with
	// watched descendants (addRecursive watches each subdir). Drop the whole
	// subtree explicitly so the fsnotify watch set stays bounded rather than
	// relying on backend auto-removal (§8 bug 15, remove-half).
	if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
		w.removeWatchTree(ev.Name)
	}

	created := ev.Op&(fsnotify.Create|fsnotify.Rename) != 0

	w.mu.Lock()
	p := w.pending[ev.Name]
	if p == nil {
		p = &pending{}
		w.pending[ev.Name] = p
	}
	if created {
		p.created = true
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	name := ev.Name
	p.timer = time.AfterFunc(w.debounce, func() { w.emit(name) })
	w.mu.Unlock()
}

func (w *Watcher) emit(realPath string) {
	w.mu.Lock()
	p := w.pending[realPath]
	delete(w.pending, realPath)
	w.mu.Unlock()
	if p == nil {
		return
	}

	vpath := w.vpathOf(realPath)
	if vpath == "" {
		return
	}

	info, err := os.Stat(realPath)
	if err != nil {
		// Gone: a removal (or rename away).
		w.onEvent(Event{Op: proto.FsRemoved, Kind: proto.KindFile, VPath: vpath})
		return
	}

	op := proto.FsModified
	if p.created {
		op = proto.FsCreated
	}
	kind := proto.KindFile
	if info.IsDir() {
		kind = proto.KindDir
	}
	mt := info.ModTime().Unix()
	if mt < 0 {
		mt = 0
	}
	w.onEvent(Event{
		Op:    op,
		Kind:  kind,
		VPath: vpath,
		Size:  uint64(info.Size()),
		Mtime: uint64(mt),
	})
}

// vpathOf converts a real path to a virtual path (slash-separated, rooted at
// "/"), or "" if it lies outside the root.
func (w *Watcher) vpathOf(realPath string) string {
	rel, err := filepath.Rel(w.root, realPath)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" {
		return "/"
	}
	if strings.HasPrefix(rel, "../") || rel == ".." {
		return ""
	}
	return "/" + rel
}
