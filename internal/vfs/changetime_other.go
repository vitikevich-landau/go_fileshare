//go:build !linux && !darwin

package vfs

import "io/fs"

// changeTimeNanos reports (0, false) where no dependable change-time is exposed
// (e.g. Windows: NTFS has a change time but Go's os.Stat does not surface it).
// ok=false tells the checksum cache it cannot prove a cached entry is still
// fresh from (size, mtime) alone — a same-size replacement that preserves the
// exact mtime would otherwise return a stale checksum — so the cache recomputes
// instead of serving a possibly-stale hit (R3-5). The daemon targets Linux,
// where the real ctime is used (see changetime_linux.go).
func changeTimeNanos(info fs.FileInfo) (int64, bool) { return 0, false }
