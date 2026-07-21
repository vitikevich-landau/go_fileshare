package vfs

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// buildShare creates a share tree and returns (shareRoot, parentDir).
func buildShare(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "share")
	mustMkdir(t, root)
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	mustWrite(t, filepath.Join(root, "zed.txt"), "zzz")
	mustWrite(t, filepath.Join(root, "файл с пробелом.txt"), "юникод")
	mustMkdir(t, filepath.Join(root, "sub"))
	mustWrite(t, filepath.Join(root, "sub", "nested.txt"), "deep")
	mustMkdir(t, filepath.Join(root, "empty"))
	// a secret sibling OUTSIDE the share root
	mustWrite(t, filepath.Join(parent, "secret.txt"), "TOP SECRET")
	return root, parent
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newVFS(t *testing.T, root string) *VFS {
	t.Helper()
	v, err := New(root, filepath.Join(t.TempDir(), "checksums.cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestListRootSorted(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)

	clean, entries, err := v.List("/")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "/" {
		t.Fatalf("clean path = %q, want /", clean)
	}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Name
	}
	// Directories first (empty, sub), then files by name.
	want := []string{"empty", "sub", "a.txt", "zed.txt", "файл с пробелом.txt"}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entries = %v, want %v", got, want)
		}
	}
	// Kinds
	if entries[0].Kind != proto.KindDir || entries[2].Kind != proto.KindFile {
		t.Fatalf("kinds wrong: %+v", entries)
	}
	// Size of a.txt = len("hello") = 5
	for _, e := range entries {
		if e.Name == "a.txt" && e.Size != 5 {
			t.Fatalf("a.txt size = %d, want 5", e.Size)
		}
	}
}

func TestListEmptyDir(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)
	_, entries, err := v.List("/empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir listing = %v", entries)
	}
}

func TestListOnFileIsNotADirectory(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)
	_, _, err := v.List("/a.txt")
	if err == nil || CodeOf(err) != proto.ErrNotADirectory {
		t.Fatalf("List on file: err=%v code=%v, want NOT_A_DIRECTORY", err, CodeOf(err))
	}
}

func TestStatNotFound(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)
	_, _, err := v.Stat("/does-not-exist")
	if err == nil || CodeOf(err) != proto.ErrFileNotFound {
		t.Fatalf("Stat missing: err=%v code=%v, want FILE_NOT_FOUND", err, CodeOf(err))
	}
}

func TestOpenDirIsADirectory(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)
	_, _, err := v.Open("/sub")
	if err == nil || CodeOf(err) != proto.ErrIsADirectory {
		t.Fatalf("Open dir: err=%v code=%v, want IS_A_DIRECTORY", err, CodeOf(err))
	}
}

func TestChecksumMatchesAndCaches(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)

	_, algo, sum, err := v.Checksum("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if algo != proto.AlgoSHA256 {
		t.Fatalf("algo = %v, want SHA256", algo)
	}
	want := sha256.Sum256([]byte("hello"))
	if sum != want {
		t.Fatalf("checksum = %x, want %x", sum, want)
	}
	// Second call must hit the cache and return the same value.
	_, _, sum2, err := v.Checksum("/a.txt")
	if err != nil || sum2 != want {
		t.Fatalf("cached checksum = %x (err %v), want %x", sum2, err, want)
	}
	v.mu.Lock()
	_, cached := v.cache["/a.txt"]
	v.mu.Unlock()
	if !cached {
		t.Fatal("checksum not cached")
	}
}

func TestChecksumCachePersistAndReload(t *testing.T) {
	root, _ := buildShare(t)
	cacheFile := filepath.Join(t.TempDir(), "checksums.cache")

	v1, err := New(root, cacheFile)
	if err != nil {
		t.Fatal(err)
	}
	_, _, want, err := v1.Checksum("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Close(); err != nil { // persists
		t.Fatal(err)
	}
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	v2, err := New(root, cacheFile)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	v2.mu.Lock()
	e, ok := v2.cache["/a.txt"]
	v2.mu.Unlock()
	if !ok || e.Sum != want {
		t.Fatalf("reloaded cache missing or wrong: ok=%v sum=%x want=%x", ok, e.Sum, want)
	}
}

func TestDotDotCannotEscape(t *testing.T) {
	root, _ := buildShare(t)
	v := newVFS(t, root)

	// "/../secret.txt" cleans to "/secret.txt" — must resolve inside the root
	// (where it does not exist), never reaching the sibling file.
	_, _, err := v.Open("/../secret.txt")
	if err == nil {
		t.Fatal("Open escaping path succeeded — confinement broken")
	}
	if CodeOf(err) != proto.ErrFileNotFound {
		t.Fatalf("escape attempt code = %v, want FILE_NOT_FOUND", CodeOf(err))
	}

	// Listing "/../.." must just be the root, not the parent.
	clean, entries, err := v.List("/../..")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "/" {
		t.Fatalf("cleaned escape path = %q, want /", clean)
	}
	for _, e := range entries {
		if e.Name == "secret.txt" {
			t.Fatal("sibling secret.txt leaked into root listing")
		}
	}
}

func TestSymlinkEscapeHidden(t *testing.T) {
	root, parent := buildShare(t)
	// Create a symlink inside the share that points outside it.
	link := filepath.Join(root, "escape")
	target := filepath.Join(parent, "secret.txt")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation not permitted: %v", err)
		}
		t.Fatal(err)
	}

	v := newVFS(t, root)

	// The escaping link must not appear in the listing.
	_, entries, err := v.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "escape" {
			t.Fatal("escaping symlink surfaced in listing")
		}
	}

	// Opening through it must not read the outside file.
	f, _, err := v.Open("/escape")
	if err == nil {
		f.Close()
		t.Fatal("opened a symlink escaping the root")
	}
}

func TestCleanPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"a/b", "/a/b"},
		{"/a//b/", "/a/b"},
		{"/a/../b", "/b"},
		{"/../../etc", "/etc"},
		{"/a/./b/", "/a/b"},
	}
	for _, c := range cases {
		got, err := CleanPath(c.in)
		if err != nil {
			t.Fatalf("CleanPath(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("CleanPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := CleanPath("a\x00b"); err == nil {
		t.Error("CleanPath with NUL should fail")
	}
}
