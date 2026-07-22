package vfs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// diskCache — форма checksum-кэша НА ДИСКЕ (JSON). Отличается от представления в
// памяти: сумма хранится строкой hex, а не массивом байт, чтобы файл кэша был
// человекочитаемым.
type diskCache struct {
	Entries map[string]diskEntry `json:"entries"` // ключ — CleanedPath
}

// diskEntry — одна запись checksum-кэша на диске (см. cacheEntry — её аналог в
// памяти).
type diskEntry struct {
	Size  uint64 `json:"size"`            // размер на момент подсчёта
	Mtime uint64 `json:"mtime"`           // mtime в наносекундах
	Ctime int64  `json:"ctime,omitempty"` // ctime в наносекундах (0 — не было)
	Algo  uint8  `json:"algo"`            // алгоритм суммы
	Sum   string `json:"sum"`             // сама сумма в hex
}

func (v *VFS) loadCache() error {
	b, err := os.ReadFile(v.cacheFile)
	if err != nil {
		return err
	}
	var dc diskCache
	if err := json.Unmarshal(b, &dc); err != nil {
		return err
	}
	cache := make(map[string]cacheEntry, len(dc.Entries))
	for k, de := range dc.Entries {
		raw, err := hex.DecodeString(de.Sum)
		if err != nil || len(raw) != proto.ChecksumLen {
			continue
		}
		var sum [proto.ChecksumLen]byte
		copy(sum[:], raw)
		cache[k] = cacheEntry{Size: de.Size, Mtime: de.Mtime, Ctime: de.Ctime, Algo: proto.Algo(de.Algo), Sum: sum}
	}
	v.mu.Lock()
	v.cache = cache
	v.dirty = false
	v.mu.Unlock()
	return nil
}

// SaveCache атомарно пишет checksum-кэш на диск (временный файл + rename), но
// только если есть несохранённые изменения. Ничего не делает, если файл кэша не
// задан. Приём «temp + rename» гарантирует, что на диске всегда лежит либо
// старый целый файл, либо новый целый — но не обрезанный на полуслове.
func (v *VFS) SaveCache() error {
	if v.cacheFile == "" {
		return nil
	}
	v.mu.Lock()
	if !v.dirty {
		v.mu.Unlock()
		return nil
	}
	dc := diskCache{Entries: make(map[string]diskEntry, len(v.cache))}
	for k, e := range v.cache {
		dc.Entries[k] = diskEntry{Size: e.Size, Mtime: e.Mtime, Ctime: e.Ctime, Algo: uint8(e.Algo), Sum: hex.EncodeToString(e.Sum[:])}
	}
	v.mu.Unlock()

	b, err := json.MarshalIndent(dc, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.cacheFile)
	tmp, err := os.CreateTemp(dir, ".checksums-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // после успешного rename — уже нечего удалять
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, v.cacheFile); err != nil {
		return err
	}
	v.mu.Lock()
	v.dirty = false
	v.mu.Unlock()
	return nil
}
