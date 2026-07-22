// Package tui реализует интерактивный клиент fileshare-commander как программу
// Bubble Tea. Логика состояния и навигации (Model/Panel) свободна от терминальных
// типов, поэтому её можно юнит-тестировать напрямую (docs/tz/09-go-port.md §5.9,
// docs/tz/04-tui-client.md §7).
//
// Архитектура (Model–Update–View, сеть вне UI-потока) и словарь типов описаны в
// types.go — прочитайте его первым.
package tui

import (
	"fmt"
	"sort"
)

// Entry — одна строка в панели: объект локальной или удалённой файловой системы.
type Entry struct {
	Name    FileName
	IsDir   bool
	Size    ByteSize
	Mtime   int64
	IsNew   bool // mtime новее снимка «виделось до» у панели → подсветка нового
	HasPart bool // рядом есть «.part» (недокачанный файл) → можно докачать
	IsUp    bool // синтетическая запись «..» (родитель)
}

// sortMode выбирает порядок сортировки панели (F2 переключает по кругу).
type sortMode int

const (
	sortByName sortMode = iota
	sortBySize
	sortByDate
	sortModeCount
)

func (s sortMode) String() string {
	switch s {
	case sortBySize:
		return "size"
	case sortByDate:
		return "date"
	default:
		return "name"
	}
}

// sortEntries orders directories before files, then by name (default order).
func sortEntries(es []Entry) { sortEntriesBy(es, sortByName) }

// sortEntriesBy orders directories before files, then by the chosen key. Size
// and date sort largest/newest first; ties fall back to name.
func sortEntriesBy(es []Entry, mode sortMode) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].IsDir != es[j].IsDir {
			return es[i].IsDir
		}
		switch mode {
		case sortBySize:
			if es[i].Size != es[j].Size {
				return es[i].Size > es[j].Size
			}
		case sortByDate:
			if es[i].Mtime != es[j].Mtime {
				return es[i].Mtime > es[j].Mtime
			}
		}
		return es[i].Name < es[j].Name
	})
}

// formatSize выводит число байт в компактной человекочитаемой форме (B/K/M/G…).
func formatSize(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
