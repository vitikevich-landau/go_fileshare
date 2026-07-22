//go:build linux

package vfs

import (
	"io/fs"
	"syscall"
)

// changeTimeNanos returns the inode change time (ctime) in nanoseconds and true.
// Unlike mtime, ctime is updated on any content or metadata change, so it
// invalidates the checksum cache even when a replacement preserves the mtime
// (RR-5). ok is false only if the platform stat is unexpectedly unavailable, in
// which case the caller must not trust a cache hit (R3-5).
func changeTimeNanos(info fs.FileInfo) (int64, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctim.Sec)*1_000_000_000 + int64(st.Ctim.Nsec), true
	}
	return 0, false
}
