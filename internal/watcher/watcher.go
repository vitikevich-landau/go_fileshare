// Package watcher превращает изменения файлов под корнем раздачи в debounced
// (схлопнутые) события протокола. Оборачивает fsnotify (кроссплатформенно) и
// добавляет рекурсивное слежение и debounce, которые эталон на C++ делал вручную
// (docs/tz/09-go-port.md §5.7).
//
// Рекурсивное слежение, схлопывание событий и словарь путей (RealPath vs
// VirtualPath) подробно описаны в types.go.
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

// Event — схлопнутое изменение под корнем, выраженное ВИРТУАЛЬНЫМ путём. Именно
// из него сервер собирает proto.EventFs для рассылки подписчикам.
type Event struct {
	Op    proto.FsOp  // создан / изменён / удалён
	Kind  proto.Kind  // файл или директория
	VPath VirtualPath // путь от корня раздачи
	Size  uint64      // размер в байтах (для удаления не значим)
	Mtime uint64      // mtime в unix-секундах
}

// Watcher рекурсивно наблюдает за корнем раздачи и вызывает onEvent на каждое
// схлопнутое изменение.
type Watcher struct {
	root     RealPath      // абсолютный путь корня на настоящей ФС
	debounce time.Duration // пауза схлопывания событий
	onEvent  func(Event)   // куда отдавать готовое событие

	fsw *fsnotify.Watcher

	mu      sync.Mutex          // защищает pending
	pending map[string]*pending // ключ — RealPath; отложенные (ещё не схлопнутые) события
}

// pending — одно отложенное событие: таймер debounce плюс флаг «это было создание»
// (чтобы после схлопывания отличить FsCreated от FsModified).
type pending struct {
	timer   *time.Timer
	created bool
}

// New создаёт watcher с корнем root. Наблюдение не начинается до вызова Start.
func New(root RealPath, debounce time.Duration, onEvent func(Event)) (*Watcher, error) {
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

// Start запускает цикл событий в отдельной горутине до отмены ctx, затем
// закрывает watcher. Ошибки fsnotify молча дренируются: одна сбойная запись не
// должна убивать всё слежение.
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

// removeWatchTree снимает слежение с dir и со всех ещё зарегистрированных
// поддиректорий, чтобы удаление/переименование непустого поддерева не оставляло
// «утёкшие» подписки на подкаталоги, которые создал addRecursive.
func (w *Watcher) removeWatchTree(dir RealPath) {
	_ = w.fsw.Remove(dir)
	prefix := dir + string(os.PathSeparator)
	for _, p := range w.fsw.WatchList() {
		if strings.HasPrefix(p, prefix) {
			_ = w.fsw.Remove(p)
		}
	}
}

// addRecursive подписывается на dir и все её поддиректории (fsnotify не
// рекурсивен, поэтому обходим дерево сами).
func (w *Watcher) addRecursive(dir RealPath) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // пропускаем нечитаемые записи, продолжаем обход
		}
		if d.IsDir() {
			_ = w.fsw.Add(path)
		}
		return nil
	})
}

func (w *Watcher) handle(ev fsnotify.Event) {
	// Только что созданную директорию тоже нужно начать слушать (fsnotify не
	// рекурсивен), включая детей, созданных до того, как мы её добавили.
	if ev.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			_ = w.addRecursive(ev.Name)
		}
	}

	// Удалённый или переименованный путь мог быть отслеживаемой директорией с
	// отслеживаемыми потомками (addRecursive слушает каждый подкаталог). Явно
	// снимаем всё поддерево, чтобы набор подписок fsnotify оставался ограниченным,
	// а не полагаемся на авто-удаление в бэкенде (§8 bug 15, remove-half).
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

// emit вызывается таймером debounce: снимает отложенную запись, определяет тип
// изменения (создан/изменён/удалён) по актуальному состоянию файла и отдаёт
// готовое Event наружу. Если путь уже вне корня — событие не рождается.
func (w *Watcher) emit(realPath RealPath) {
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
		// Пути больше нет: удаление (или переименование прочь).
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

// vpathOf переводит настоящий путь в виртуальный (разделитель «/», от корня «/»)
// или "" если путь лежит вне корня. Это шаг RealPath → VirtualPath из types.go.
func (w *Watcher) vpathOf(realPath RealPath) VirtualPath {
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
