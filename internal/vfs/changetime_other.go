//go:build !linux && !darwin

package vfs

import "io/fs"

// changeTimeNanos возвращает (0, false) там, где надёжного change-time нет
// (например, Windows: у NTFS время изменения есть, но os.Stat в Go его не
// отдаёт). ok == false сообщает checksum-кэшу, что по паре (size, mtime) нельзя
// доказать свежесть записи — подмена тем же размером с сохранённым точным mtime
// иначе вернула бы устаревшую сумму, — поэтому кэш пересчитывает, а не отдаёт
// возможно-протухший результат (R3-5). Демон нацелен на Linux, где используется
// настоящий ctime (см. changetime_linux.go).
func changeTimeNanos(info fs.FileInfo) (int64, bool) { return 0, false }
