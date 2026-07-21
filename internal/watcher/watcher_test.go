package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

func waitEvent(t *testing.T, ch <-chan Event, match func(Event) bool) Event {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching event")
		}
	}
}

func TestWatcherReportsCreate(t *testing.T) {
	root := t.TempDir()
	ch := make(chan Event, 16)
	w, err := New(root, 30*time.Millisecond, func(e Event) { ch <- e })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, ch, func(e Event) bool { return e.VPath == "/hello.txt" })
	if ev.Op != proto.FsCreated || ev.Size != 2 {
		t.Fatalf("event = %+v, want CREATED size 2", ev)
	}
}

func TestWatcherRecursiveNewSubdir(t *testing.T) {
	root := t.TempDir()
	ch := make(chan Event, 16)
	w, err := New(root, 30*time.Millisecond, func(e Event) { ch <- e })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	// Create a new subdirectory, then a file inside it: the watcher must have
	// added a watch on the new dir (fsnotify is not recursive).
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Give the watcher a moment to register the new directory.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(sub, "deep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	ev := waitEvent(t, ch, func(e Event) bool { return e.VPath == "/sub/deep.txt" })
	if ev.Op != proto.FsCreated || ev.Kind != proto.KindFile {
		t.Fatalf("event = %+v, want CREATED file", ev)
	}
}

func TestWatcherReportsRemove(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "gone.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan Event, 16)
	w, err := New(root, 30*time.Millisecond, func(e Event) { ch <- e })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, ch, func(e Event) bool { return e.VPath == "/gone.txt" })
	if ev.Op != proto.FsRemoved {
		t.Fatalf("event op = %v, want REMOVED", ev.Op)
	}
}
