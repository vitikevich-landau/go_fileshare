package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// ErrNoSuchUser is returned when updating a user that does not exist.
var ErrNoSuchUser = errors.New("auth: no such user")

// Record is one user entry in users.json. StoredKey is hex(SHA256(ClientKey)).
type Record struct {
	Login     string `json:"login"`
	Role      string `json:"role"` // "admin" | "user"
	StoredKey string `json:"stored_key"`
	Enabled   bool   `json:"enabled"`
}

type fileForm struct {
	Users []Record `json:"users"`
}

// DB is the user database. It is safe for concurrent use.
type DB struct {
	path string

	mu      sync.RWMutex
	byLogin map[string]Record
	order   []string
}

// Load reads users.json from path. A missing file yields an empty DB (the
// no-auth bootstrap: any login authenticates as ADMIN), which is not an error.
func Load(path string) (*DB, error) {
	db := &DB{path: path, byLogin: map[string]Record{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	var ff fileForm
	if err := json.Unmarshal(b, &ff); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for _, r := range ff.Users {
		if _, dup := db.byLogin[r.Login]; !dup {
			db.order = append(db.order, r.Login)
		}
		db.byLogin[r.Login] = r
	}
	return db, nil
}

// Empty reports whether the DB has no users (no-auth bootstrap).
func (db *DB) Empty() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.byLogin) == 0
}

// Lookup returns the decoded StoredKey, role, and enabled flag for a login.
func (db *DB) Lookup(login string) (storedKey [proto.ChecksumLen]byte, role proto.Role, enabled, ok bool) {
	db.mu.RLock()
	r, found := db.byLogin[login]
	db.mu.RUnlock()
	if !found {
		return storedKey, proto.RoleUser, false, false
	}
	raw, err := hex.DecodeString(r.StoredKey)
	if err != nil || len(raw) != proto.ChecksumLen {
		return storedKey, proto.RoleUser, false, false
	}
	copy(storedKey[:], raw)
	return storedKey, roleFromString(r.Role), r.Enabled, true
}

// SetUser adds or replaces a user, computing StoredKey from the password using
// the given iteration count.
func (db *DB) SetUser(login string, role proto.Role, password string, iters int) {
	sk := StoredKey(password, login, iters)
	rec := Record{
		Login:     login,
		Role:      roleToString(role),
		StoredKey: hex.EncodeToString(sk[:]),
		Enabled:   true,
	}
	db.mu.Lock()
	if _, ok := db.byLogin[login]; !ok {
		db.order = append(db.order, login)
	}
	db.byLogin[login] = rec
	db.mu.Unlock()
}

// SetPassword resets an existing user's password. It errors if the user is
// absent.
func (db *DB) SetPassword(login, password string, iters int) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, ok := db.byLogin[login]
	if !ok {
		return ErrNoSuchUser
	}
	sk := StoredKey(password, login, iters)
	r.StoredKey = hex.EncodeToString(sk[:])
	db.byLogin[login] = r
	return nil
}

// SetEnabled toggles a user's enabled flag. It errors if the user is absent.
func (db *DB) SetEnabled(login string, enabled bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, ok := db.byLogin[login]
	if !ok {
		return ErrNoSuchUser
	}
	r.Enabled = enabled
	db.byLogin[login] = r
	return nil
}

// Save atomically writes the DB to its file (temp + rename).
func (db *DB) Save() error {
	db.mu.RLock()
	ff := fileForm{Users: make([]Record, 0, len(db.order))}
	for _, login := range db.order {
		if r, ok := db.byLogin[login]; ok {
			ff.Users = append(ff.Users, r)
		}
	}
	db.mu.RUnlock()

	b, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(db.path)
	tmp, err := os.CreateTemp(dir, ".users-*.tmp")
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
	return os.Rename(tmpName, db.path)
}

func roleFromString(s string) proto.Role {
	switch s {
	case "admin":
		return proto.RoleAdmin
	case "user":
		return proto.RoleUser
	}
	return proto.RoleUser
}

func roleToString(r proto.Role) string {
	if r == proto.RoleAdmin {
		return "admin"
	}
	return "user"
}

// RoleFromString exposes role parsing for CLI flags.
func RoleFromString(s string) (proto.Role, bool) {
	switch s {
	case "admin":
		return proto.RoleAdmin, true
	case "user":
		return proto.RoleUser, true
	}
	return proto.RoleUser, false
}
