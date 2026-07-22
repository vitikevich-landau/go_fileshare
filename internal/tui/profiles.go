package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Profile — сохранённое подключение (docs/tz/04-tui-client.md §6,
// docs/tz/09-go-port.md §12.3): чтобы не вводить хост/порт/логин каждый раз.
type Profile struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Login        string `json:"login"`
	Secret       string `json:"secret,omitempty"` // зарезервировано под «запомнить пароль»
	LastSeen     int64  `json:"last_seen"`        // для подсветки новых файлов между визитами
	DownloadsDir string `json:"downloads_dir"`
}

// Profiles — сохранённый на диске НАБОР профилей подключения (в конфиг-каталоге).
type Profiles struct {
	Profiles []Profile `json:"profiles"`
	path     string
}

// configDir returns the fileshare config directory: %APPDATA%\fileshare on
// Windows, else $XDG_CONFIG_HOME/fileshare or ~/.config/fileshare.
func configDir() string {
	if runtime.GOOS == "windows" {
		if ad := os.Getenv("APPDATA"); ad != "" {
			return filepath.Join(ad, "fileshare")
		}
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "fileshare")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "fileshare"
	}
	return filepath.Join(home, ".config", "fileshare")
}

func profilesPath() string { return filepath.Join(configDir(), "profiles.json") }

// LoadProfiles reads profiles.json, returning an empty set if it is absent.
func LoadProfiles() *Profiles {
	p := &Profiles{path: profilesPath()}
	b, err := os.ReadFile(p.path)
	if err != nil {
		return p
	}
	_ = json.Unmarshal(b, p)
	return p
}

// Find returns the profile with the given name.
func (p *Profiles) Find(name string) (Profile, bool) {
	for _, pr := range p.Profiles {
		if pr.Name == name {
			return pr, true
		}
	}
	return Profile{}, false
}

// Upsert inserts or replaces a profile by name.
func (p *Profiles) Upsert(prof Profile) {
	for i := range p.Profiles {
		if p.Profiles[i].Name == prof.Name {
			p.Profiles[i] = prof
			return
		}
	}
	p.Profiles = append(p.Profiles, prof)
}

// Save writes profiles.json atomically with 0600 permissions.
func (p *Profiles) Save() error {
	if p.path == "" {
		p.path = profilesPath()
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(struct {
		Profiles []Profile `json:"profiles"`
	}{p.Profiles}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".profiles-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, p.path)
}
