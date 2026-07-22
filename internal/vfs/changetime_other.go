//go:build !linux

package vfs

import "io/fs"

// changeTimeNanos falls back to 0 where a portable change-time is unavailable
// (e.g. Windows); the cache then relies on size + nanosecond mtime. The daemon
// targets Linux, where the real ctime is used (see changetime_linux.go).
func changeTimeNanos(info fs.FileInfo) int64 { return 0 }
