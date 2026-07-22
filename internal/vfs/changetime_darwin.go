//go:build darwin

package vfs

import (
	"io/fs"
	"syscall"
)

// changeTimeNanos returns the inode change time (ctime) in nanoseconds and true.
// Like the Linux path, ctime moves on any content or metadata change, so it
// invalidates the checksum cache even when a replacement preserves the mtime
// (RR-5, R3-5). ok is false only if the platform stat is unexpectedly
// unavailable, in which case the caller must not trust a cache hit.
func changeTimeNanos(info fs.FileInfo) (int64, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctimespec.Sec)*1_000_000_000 + int64(st.Ctimespec.Nsec), true
	}
	return 0, false
}
