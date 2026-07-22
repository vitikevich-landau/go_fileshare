// Package vfs serves a directory tree confined to a share root.
//
// Path confinement is delegated to os.Root (Go 1.24+), which keeps every
// operation beneath the root even in the presence of ".." components or
// symlinks pointing outside — this replaces the hand-rolled openat2/realpath
// logic of the C++ reference and closes the TOCTOU class by design
// (docs/tz/09-go-port.md §5.2, §7).
package vfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// Error carries a protocol error code alongside the underlying cause, so the
// server can translate a VFS failure into the right ERROR frame.
type Error struct {
	Code proto.ErrCode
	Op   string
	Path string
	Err  error
}

func (e *Error) Error() string {
	return fmt.Sprintf("vfs %s %q: %v (%s)", e.Op, e.Path, e.Err, e.Code)
}
func (e *Error) Unwrap() error { return e.Err }

// CodeOf extracts the protocol error code from an error returned by this
// package, defaulting to INTERNAL_ERROR.
func CodeOf(err error) proto.ErrCode {
	var ve *Error
	if errors.As(err, &ve) {
		return ve.Code
	}
	return proto.ErrInternal
}

var errBadPath = errors.New("malformed path")

// classify maps an OS-level error to a protocol error code. Anything a confined
// os.Root refuses that is not a plain not-found/permission case (most notably a
// symlink or component escaping the root) is reported as ACCESS_DENIED.
func classify(err error) proto.ErrCode {
	// The ENOTDIR/EISDIR checks must precede the fs.ErrNotExist check: on
	// Windows syscall.ENOTDIR reports itself as fs.ErrNotExist via Errno.Is,
	// which would otherwise mislabel a "not a directory" as "file not found".
	switch {
	case errors.Is(err, errBadPath):
		return proto.ErrBadRequest
	case errors.Is(err, syscall.ENOTDIR):
		return proto.ErrNotADirectory
	case errors.Is(err, syscall.EISDIR):
		return proto.ErrIsADirectory
	case errors.Is(err, fs.ErrNotExist):
		return proto.ErrFileNotFound
	case errors.Is(err, fs.ErrPermission):
		return proto.ErrAccessDenied
	}
	return proto.ErrAccessDenied
}

func coded(op, p string, err error) *Error {
	return &Error{Code: classify(err), Op: op, Path: p, Err: err}
}

// VFS is a directory tree rooted at a share directory, with a lazy checksum
// cache. It is safe for concurrent use.
type VFS struct {
	root      *os.Root
	rootName  string
	cacheFile string

	mu    sync.Mutex
	cache map[string]cacheEntry
	dirty bool
}

type cacheEntry struct {
	Size  uint64
	Mtime uint64
	Ctime int64 // change-time nanos where available (0 otherwise) — RR-5
	Algo  proto.Algo
	Sum   [proto.ChecksumLen]byte
}

// New opens shareRoot as a confined root. If cacheFile is non-empty and exists,
// the checksum cache is loaded from it.
func New(shareRoot, cacheFile string) (*VFS, error) {
	root, err := os.OpenRoot(shareRoot)
	if err != nil {
		return nil, fmt.Errorf("vfs: open share root %q: %w", shareRoot, err)
	}
	v := &VFS{
		root:      root,
		rootName:  shareRoot,
		cacheFile: cacheFile,
		cache:     make(map[string]cacheEntry),
	}
	if cacheFile != "" {
		if err := v.loadCache(); err != nil {
			// A corrupt/absent cache is not fatal — start empty.
			v.cache = make(map[string]cacheEntry)
		}
	}
	return v, nil
}

// Close persists the checksum cache and releases the root handle.
func (v *VFS) Close() error {
	err := v.SaveCache()
	if cerr := v.root.Close(); err == nil {
		err = cerr
	}
	return err
}

// RootName returns the share root path this VFS was opened with.
func (v *VFS) RootName() string { return v.rootName }

// CleanPath normalizes a virtual path to an absolute, slash-separated form with
// no "..", "//" or trailing slash ("/" stays "/"). ".." can never climb above
// the root because the path is cleaned as if rooted at "/". NUL bytes are
// rejected as BAD_REQUEST.
func CleanPath(vpath string) (string, error) {
	if strings.IndexByte(vpath, 0) >= 0 {
		return "", errBadPath
	}
	if vpath == "" {
		vpath = "/"
	}
	return path.Clean("/" + vpath), nil
}

// rel converts a cleaned virtual path to an OS-relative path for os.Root.
func rel(clean string) string {
	r := strings.TrimPrefix(clean, "/")
	if r == "" {
		return "."
	}
	return filepath.FromSlash(r)
}

func entryFromInfo(name string, info fs.FileInfo) proto.DirEntry {
	kind := proto.KindFile
	if info.IsDir() {
		kind = proto.KindDir
	}
	mt := info.ModTime().Unix()
	if mt < 0 {
		mt = 0
	}
	return proto.DirEntry{
		Name:  name,
		Kind:  kind,
		Size:  uint64(info.Size()),
		Mtime: uint64(mt),
	}
}

// List returns the entries of the directory at vpath, directories first, then
// by name. Entries that cannot be resolved within the root (e.g. symlinks
// escaping it, or broken links) are hidden rather than surfaced.
func (v *VFS) List(vpath string) (string, []proto.DirEntry, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", nil, coded("list", vpath, err)
	}
	info, err := v.root.Stat(rel(clean))
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}
	if !info.IsDir() {
		return clean, nil, coded("list", clean, syscall.ENOTDIR)
	}
	f, err := v.root.Open(rel(clean))
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}
	defer f.Close()

	dirents, err := f.ReadDir(-1)
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}

	entries := make([]proto.DirEntry, 0, len(dirents))
	for _, de := range dirents {
		name := de.Name()
		// The wire caps a name at MaxNameLen bytes; a longer one (possible on
		// NTFS for multi-byte unicode names) would make the peer reject the
		// whole listing frame, so hide it rather than poison the response.
		if len(name) > proto.MaxNameLen {
			continue
		}
		var info fs.FileInfo
		if de.Type()&fs.ModeSymlink != 0 {
			// Resolve through the root; hide links that escape or dangle.
			child := path.Join(clean, name)
			si, serr := v.root.Stat(rel(child))
			if serr != nil {
				continue
			}
			info = si
		} else {
			li, ierr := de.Info()
			if ierr != nil {
				continue
			}
			info = li
		}
		entries = append(entries, entryFromInfo(name, info))
	}

	sort.Slice(entries, func(i, j int) bool {
		di := entries[i].Kind == proto.KindDir
		dj := entries[j].Kind == proto.KindDir
		if di != dj {
			return di // directories first
		}
		return entries[i].Name < entries[j].Name
	})
	return clean, entries, nil
}

// Stat returns metadata for a single entry at vpath.
func (v *VFS) Stat(vpath string) (string, proto.DirEntry, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", proto.DirEntry{}, coded("stat", vpath, err)
	}
	info, err := v.root.Stat(rel(clean))
	if err != nil {
		return clean, proto.DirEntry{}, coded("stat", clean, err)
	}
	return clean, entryFromInfo(path.Base(clean), info), nil
}

// Open opens the file at vpath for reading, confined to the root. The caller is
// responsible for closing it. Directories are refused with IS_A_DIRECTORY.
func (v *VFS) Open(vpath string) (*os.File, fs.FileInfo, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return nil, nil, coded("open", vpath, err)
	}
	f, err := v.root.Open(rel(clean))
	if err != nil {
		return nil, nil, coded("open", clean, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, coded("open", clean, err)
	}
	if info.IsDir() {
		f.Close()
		return nil, nil, coded("open", clean, syscall.EISDIR)
	}
	return f, info, nil
}

// Checksum returns the checksum of the file at vpath, computing it lazily and
// caching by (path, size, mtime). The current algorithm is SHA-256.
func (v *VFS) Checksum(vpath string) (string, proto.Algo, [proto.ChecksumLen]byte, error) {
	var zero [proto.ChecksumLen]byte
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", proto.AlgoPending, zero, coded("checksum", vpath, err)
	}
	f, info, err := v.Open(clean)
	if err != nil {
		return clean, proto.AlgoPending, zero, err
	}
	defer f.Close()

	size := uint64(info.Size())
	// Nanosecond mtime granularity (CR-09) plus change-time (RR-5): ctime
	// changes on any content/metadata modification even when mtime is preserved
	// (unix), catching a same-size same-mtime replacement. This is the cache key
	// only; the wire DirEntry.mtime stays unix seconds.
	mtime := uint64(info.ModTime().UnixNano())
	ctime, ctimeOK := changeTimeNanos(info)

	// Only trust a cache hit when the platform gives a dependable change-time.
	// Where it does not (e.g. Windows), (size, mtime) alone cannot prove the
	// content is unchanged — a same-size replacement with the exact mtime
	// restored would return a stale checksum — so recompute instead (R3-5).
	v.mu.Lock()
	if e, ok := v.cache[clean]; ok && ctimeOK && e.Size == size && e.Mtime == mtime && e.Ctime == ctime {
		v.mu.Unlock()
		return clean, e.Algo, e.Sum, nil
	}
	v.mu.Unlock()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return clean, proto.AlgoPending, zero, coded("checksum", clean, err)
	}
	var sum [proto.ChecksumLen]byte
	copy(sum[:], h.Sum(nil))

	v.mu.Lock()
	v.cache[clean] = cacheEntry{Size: size, Mtime: mtime, Ctime: ctime, Algo: proto.AlgoSHA256, Sum: sum}
	v.dirty = true
	v.mu.Unlock()
	return clean, proto.AlgoSHA256, sum, nil
}

// InvalidateChecksum drops any cached checksum for vpath (called when the
// watcher reports a change).
func (v *VFS) InvalidateChecksum(vpath string) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return
	}
	v.mu.Lock()
	if _, ok := v.cache[clean]; ok {
		delete(v.cache, clean)
		v.dirty = true
	}
	v.mu.Unlock()
}
