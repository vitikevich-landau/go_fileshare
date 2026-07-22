//go:build linux

package vfs

import (
	"io/fs"
	"syscall"
)

// changeTimeNanos возвращает время изменения inode (ctime) в наносекундах и
// true. В отличие от mtime, ctime обновляется при ЛЮБОМ изменении содержимого
// или метаданных, поэтому сбрасывает checksum-кэш, даже когда подмена сохранила
// mtime (RR-5). ok == false только если stat платформы неожиданно недоступен —
// тогда вызывающий не должен доверять попаданию в кэш (R3-5).
func changeTimeNanos(info fs.FileInfo) (int64, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctim.Sec)*1_000_000_000 + int64(st.Ctim.Nsec), true
	}
	return 0, false
}
