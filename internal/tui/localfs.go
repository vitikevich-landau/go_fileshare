package tui

import (
	"os"
	"path/filepath"
	"strings"
)

// readLocalDir lists a local directory into panel entries. It returns the
// cleaned absolute path and whether a parent exists.
func readLocalDir(dir string) (entries []Entry, abs string, hasParent bool, err error) {
	abs, err = filepath.Abs(dir)
	if err != nil {
		return nil, dir, false, err
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		return nil, abs, false, err
	}

	// Collect the set of ".part" basenames so we can flag partial downloads.
	partOf := map[string]bool{}
	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".part") {
			partOf[strings.TrimSuffix(de.Name(), ".part")] = true
		}
	}

	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".part") {
			continue // hide the .part shadow file itself
		}
		info, ierr := de.Info()
		if ierr != nil {
			continue
		}
		entries = append(entries, Entry{
			Name:    de.Name(),
			IsDir:   de.IsDir(),
			Size:    uint64(info.Size()),
			Mtime:   info.ModTime().Unix(),
			HasPart: partOf[de.Name()],
		})
	}
	hasParent = filepath.Dir(abs) != abs
	return entries, abs, hasParent, nil
}
