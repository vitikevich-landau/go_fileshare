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

// ErrNoSuchUser возвращается при попытке изменить несуществующего пользователя.
var ErrNoSuchUser = errors.New("auth: no such user")

// Record — одна запись пользователя в users.json. Ключевой момент: хранится не
// пароль и не его хеш, а только StoredKey (hex от SHA256(ClientKey)) — верификатор,
// из которого нельзя ни узнать пароль, ни собрать доказательство.
type Record struct {
	Login     Login  `json:"login"`
	Role      string `json:"role"` // "admin" | "user"
	StoredKey string `json:"stored_key"`
	Enabled   bool   `json:"enabled"`
}

// fileForm — обёртка верхнего уровня JSON-файла users.json ({"users": [...]}).
type fileForm struct {
	Users []Record `json:"users"`
}

// DB — база пользователей. Безопасна для конкурентного использования (RWMutex).
type DB struct {
	path string

	mu      sync.RWMutex
	byLogin map[string]Record // логин → запись (для быстрого поиска)
	order   []string          // логины в порядке добавления (для стабильной записи)
}

// Load читает users.json по пути path. ОТСУТСТВУЮЩИЙ файл даёт пустую БД (это и
// есть bootstrap без аутентификации: любой логин входит как ADMIN) и НЕ считается
// ошибкой. Сравните с Reload ниже, где отсутствие файла — уже ошибка.
func Load(path string) (*DB, error) {
	db := &DB{path: path, byLogin: map[string]Record{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	byLogin, order, err := parseUsersFile(b)
	if err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	db.byLogin, db.order = byLogin, order
	return db, nil
}

// parseUsersFile разбирает тело users.json в карту по логину и порядок вставки.
// Дубликаты логинов не задваивают порядок: побеждает последняя запись.
func parseUsersFile(b []byte) (map[string]Record, []string, error) {
	var ff fileForm
	if err := json.Unmarshal(b, &ff); err != nil {
		return nil, nil, err
	}
	byLogin := map[string]Record{}
	var order []string
	for _, r := range ff.Users {
		if _, dup := byLogin[r.Login]; !dup {
			order = append(order, r.Login)
		}
		byLogin[r.Login] = r
	}
	return byLogin, order, nil
}

// Reload перечитывает файл пользователей с диска, заменяя набор в памяти.
// Используется для ГОРЯЧЕГО управления учётками (SIGHUP / запрос админа): включение,
// отключение или добавление пользователя вступает в силу без перезапуска
// (docs/tz/03-server-daemon.md §3.3).
//
// В отличие от стартового Load, ОТСУТСТВУЮЩИЙ или нечитаемый файл здесь — ошибка,
// а не пустая bootstrap-БД: молча опустошить набор при reload означало бы
// перевести демон в режим без аутентификации (любой логин = ADMIN) после случайного
// удаления или переименования. При любой ошибке текущий набор в памяти остаётся
// нетронутым (fail closed — «падаем в закрытое, безопасное состояние»).
func (db *DB) Reload() error {
	b, err := os.ReadFile(db.path)
	if err != nil {
		return fmt.Errorf("auth: reload %s: %w", db.path, err)
	}
	byLogin, order, err := parseUsersFile(b)
	if err != nil {
		return fmt.Errorf("auth: reload parse %s: %w", db.path, err)
	}
	db.mu.Lock()
	db.byLogin, db.order = byLogin, order
	db.mu.Unlock()
	return nil
}

// Empty сообщает, что в БД нет пользователей (режим bootstrap без аутентификации).
func (db *DB) Empty() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.byLogin) == 0
}

// Lookup возвращает раскодированный StoredKey, роль и флаг «включён» для логина.
// ok == false, если пользователя нет или его StoredKey в файле повреждён.
func (db *DB) Lookup(login Login) (storedKey [proto.ChecksumLen]byte, role proto.Role, enabled, ok bool) {
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

// SetUser добавляет или заменяет пользователя, вычисляя StoredKey из пароля с
// заданным числом итераций. Пароль после этого нигде не сохраняется.
func (db *DB) SetUser(login Login, role proto.Role, password Password, iters Iterations) {
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

// SetPassword сбрасывает пароль существующего пользователя. Возвращает ошибку,
// если такого пользователя нет.
func (db *DB) SetPassword(login Login, password Password, iters Iterations) error {
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

// SetEnabled переключает флаг «включён» у пользователя. Возвращает ошибку, если
// такого пользователя нет.
func (db *DB) SetEnabled(login Login, enabled bool) error {
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

// Save атомарно пишет БД в свой файл (временный файл + rename), сохраняя порядок
// добавления пользователей. Атомарность защищает от «полузаписанного» users.json.
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

// RoleFromString разбирает роль из строки для флагов CLI (--role). Второе
// значение — успешно ли распознана роль.
func RoleFromString(s string) (proto.Role, bool) {
	switch s {
	case "admin":
		return proto.RoleAdmin, true
	case "user":
		return proto.RoleUser, true
	}
	return proto.RoleUser, false
}
