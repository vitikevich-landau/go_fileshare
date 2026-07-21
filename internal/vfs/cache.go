package vfs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// diskCache is the on-disk JSON form of the checksum cache.
type diskCache struct {
	Entries map[string]diskEntry `json:"entries"`
}

type diskEntry struct {
	Size  uint64 `json:"size"`
	Mtime uint64 `json:"mtime"`
	Algo  uint8  `json:"algo"`
	Sum   string `json:"sum"` // hex
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
		cache[k] = cacheEntry{Size: de.Size, Mtime: de.Mtime, Algo: proto.Algo(de.Algo), Sum: sum}
	}
	v.mu.Lock()
	v.cache = cache
	v.dirty = false
	v.mu.Unlock()
	return nil
}

// SaveCache atomically writes the checksum cache to disk (temp file + rename),
// but only when there are unsaved changes. A no-op if no cache file is set.
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
		dc.Entries[k] = diskEntry{Size: e.Size, Mtime: e.Mtime, Algo: uint8(e.Algo), Sum: hex.EncodeToString(e.Sum[:])}
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
	defer os.Remove(tmpName) // no-op after a successful rename
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
