//go:build linux

package vfs

import (
	"io/fs"
	"syscall"
)

// changeTimeNanos returns the inode change time (ctime) in nanoseconds. Unlike
// mtime, ctime is updated on any content or metadata change, so it invalidates
// the checksum cache even when a replacement preserves the mtime (RR-5).
func changeTimeNanos(info fs.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctim.Sec)*1_000_000_000 + int64(st.Ctim.Nsec)
	}
	return 0
}
