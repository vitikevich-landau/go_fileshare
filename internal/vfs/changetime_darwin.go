//go:build darwin

package vfs

import (
	"io/fs"
	"syscall"
)

// changeTimeNanos возвращает время изменения inode (ctime) в наносекундах и
// true. Как и на Linux, ctime сдвигается при любом изменении содержимого или
// метаданных, поэтому сбрасывает checksum-кэш, даже если подмена сохранила mtime
// (RR-5, R3-5). ok == false только если stat платформы неожиданно недоступен —
// тогда вызывающий не должен доверять попаданию в кэш.
func changeTimeNanos(info fs.FileInfo) (int64, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctimespec.Sec)*1_000_000_000 + int64(st.Ctimespec.Nsec), true
	}
	return 0, false
}
