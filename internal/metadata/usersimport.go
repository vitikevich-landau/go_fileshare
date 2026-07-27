package metadata

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// storedKeyLen — длина StoredKey в байтах: это SHA256(ClientKey).
//
// Значение продублировано из proto.ChecksumLen сознательно: §4.3 п. 1 запрещает
// metadata импортировать proto. Разъезд поймает первый же импорт реального
// users.json — там лежат ровно 64 hex-символа.
const storedKeyLen = 32

// legacyFile — формат users.json (`{"users": [...]}`), из которого §21.4 берёт
// пользователей.
//
// Структура объявлена здесь, а не переиспользована из internal/auth, по той же
// причине, что и storedKeyLen: auth импортирует proto. Формат заморожен — это
// вход одноразовой миграции, а не живая модель, — поэтому дублирование четырёх
// полей дешевле нарушения правила зависимостей.
type legacyFile struct {
	Users []legacyRecord `json:"users"`
}

type legacyRecord struct {
	Login     string `json:"login"`
	Role      string `json:"role"`
	StoredKey string `json:"stored_key"`
	// Enabled отсутствующий в JSON читается как false, то есть как disabled.
	// Так же его читает и сегодняшний сервер (`internal/auth/userdb.go`), а
	// миграция обязана сохранить аутентификацию, а не улучшить её.
	Enabled bool `json:"enabled"`
}

// ImportOptions — параметры импорта users.json (§21.4).
type ImportOptions struct {
	// AuthIters — auth.pbkdf2_iters из СТАРОГО конфига: значение, с которым
	// посчитаны stored_key в файле. До появления раунда AUTH_PARAMS (M14) оно
	// одинаково у всех пользователей (§3.3).
	AuthIters int
	// OverwriteExisting перезаписывает запись, уже существующую в БД с иными
	// данными, значениями из JSON. Без него такая запись прерывает миграцию.
	OverwriteExisting bool
}

// ImportReport — что миграция сделала с каждым логином. Списки отсортированы,
// чтобы вывод команды не зависел от порядка записей в файле.
type ImportReport struct {
	Created []string
	Skipped []string
	Updated []string
}

// ImportUsers переносит users.json в таблицу users (§21.4).
//
// Весь импорт выполняется ОДНОЙ транзакцией. §21.4 требует, чтобы конфликт
// прерывал миграцию; прерывание на середине оставило бы половину файла
// импортированной, и оператор не мог бы ни повторить, ни откатить операцию, не
// разбираясь вручную, где она остановилась. Всё или ничего — единственное
// состояние, из которого повтор после правки файла осмыслен.
//
// Исходный JSON не удаляется и не изменяется: файл читает вызывающий, сюда
// приходит его содержимое.
func ImportUsers(ctx context.Context, d *db.DB, us *Users, data []byte, opts ImportOptions) (ImportReport, error) {
	if opts.AuthIters <= 0 {
		return ImportReport{}, fmt.Errorf("metadata: import users: auth_iters = %d, must be > 0", opts.AuthIters)
	}
	records, err := parseLegacyUsers(data)
	if err != nil {
		return ImportReport{}, err
	}

	var rep ImportReport
	err = d.Write(ctx, func(tx *sql.Tx) error {
		rep = ImportReport{}
		for _, rec := range records {
			action, err := importOne(ctx, tx, us, rec, opts)
			if err != nil {
				return err
			}
			switch action {
			case actionCreated:
				rep.Created = append(rep.Created, rec.Login)
			case actionSkipped:
				rep.Skipped = append(rep.Skipped, rec.Login)
			case actionUpdated:
				rep.Updated = append(rep.Updated, rec.Login)
			}
		}
		return nil
	})
	if err != nil {
		return ImportReport{}, err
	}
	sort.Strings(rep.Created)
	sort.Strings(rep.Skipped)
	sort.Strings(rep.Updated)
	return rep, nil
}

type importAction int

const (
	actionCreated importAction = iota
	actionSkipped
	actionUpdated
)

func importOne(ctx context.Context, tx *sql.Tx, us *Users, rec legacyRecord, opts ImportOptions) (importAction, error) {
	want := legacyToUser(rec, opts.AuthIters)

	// Существующая запись читается ВНУТРИ транзакции: сверка по читающему
	// handle относилась бы к другому снапшоту.
	var (
		role, state, kdfAlgo string
		salt, storedKey      []byte
	)
	err := tx.QueryRowContext(ctx,
		`SELECT role, state, kdf_algo, salt, stored_key FROM users WHERE login = ?`, rec.Login).
		Scan(&role, &state, &kdfAlgo, &salt, &storedKey)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := us.Create(ctx, tx, want); err != nil {
			return 0, fmt.Errorf("metadata: import user %q: %w", rec.Login, err)
		}
		return actionCreated, nil
	}
	if err != nil {
		return 0, fmt.Errorf("metadata: import user %q: read existing: %w", rec.Login, err)
	}

	// §21.4 перечисляет поля сверки поимённо, и auth_iters в перечень НЕ входит.
	// Это не упущение: auth_iters существующей записи — то число, с которым
	// посчитан её stored_key, а конфиг с тех пор мог смениться. Взяв конфиг за
	// истину, повторный запуск сломал бы вход тем, кого он не менял.
	diff := diffFields(want, role, state, kdfAlgo, salt, storedKey)
	if len(diff) == 0 {
		return actionSkipped, nil
	}
	if !opts.OverwriteExisting {
		return 0, fmt.Errorf(
			"metadata: import user %q: the database already holds this login with different data (%s); "+
				"re-run with --overwrite-existing to replace the record with the values from the JSON (§21.4)",
			rec.Login, strings.Join(diff, ", "))
	}

	id, err := userIDByLogin(ctx, tx, rec.Login)
	if err != nil {
		return 0, err
	}
	if err := us.SetRole(ctx, tx, id, want.Role); err != nil {
		return 0, err
	}
	if err := us.SetState(ctx, tx, id, want.State); err != nil {
		return 0, err
	}
	if err := us.SetSecret(ctx, tx, id, want.Secret); err != nil {
		return 0, err
	}
	return actionUpdated, nil
}

// diffFields перечисляет РАЗЛИЧАЮЩИЕСЯ поля по-человечески: §21.4 требует
// «понятной ошибки с указанием логина и различающихся полей», а не констатации
// факта расхождения. Значения secret в сообщение не попадают: stored_key — это
// верификатор пароля, и его место не в логе оператора.
func diffFields(want NewUser, role, state, kdfAlgo string, salt, storedKey []byte) []string {
	var diff []string
	if role != string(want.Role) {
		diff = append(diff, fmt.Sprintf("role: %q in the database, %q in the JSON", role, want.Role))
	}
	if state != string(want.State) {
		diff = append(diff, fmt.Sprintf("state: %q in the database, %q in the JSON", state, want.State))
	}
	if kdfAlgo != string(want.Secret.KDFAlgo) {
		diff = append(diff, fmt.Sprintf("kdf_algo: %q in the database, %q in the JSON",
			kdfAlgo, want.Secret.KDFAlgo))
	}
	if string(salt) != string(want.Secret.Salt) {
		diff = append(diff, "salt")
	}
	if string(storedKey) != string(want.Secret.StoredKey) {
		diff = append(diff, "stored_key")
	}
	return diff
}

func userIDByLogin(ctx context.Context, tx *sql.Tx, login string) (domain.UserID, error) {
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE login = ?`, login).Scan(&id); err != nil {
		return 0, fmt.Errorf("metadata: import user %q: read id: %w", login, err)
	}
	return domain.UserID(id), nil
}

// legacyToUser отображает запись файла в строку users по правилам §21.4.
func legacyToUser(rec legacyRecord, authIters int) NewUser {
	state := domain.UserActive
	if !rec.Enabled {
		state = domain.UserDisabled
	}
	storedKey, _ := hex.DecodeString(rec.StoredKey) // формат проверен разбором
	return NewUser{
		Login: rec.Login,
		Role:  domain.Role(rec.Role),
		State: state,
		Secret: Secret{
			// §21.4: kdf_algo = 'pbkdf2-sha256' и соль — литерал
			// "fileshare-v2:"+login, воспроизводящий сегодняшнее
			// детерминированное выведение соли. Иначе миграция сломала бы
			// аутентификацию: до раунда AUTH_PARAMS клиент считает соль сам.
			KDFAlgo:   domain.KDFPBKDF2SHA256,
			Salt:      domain.LegacySalt(rec.Login),
			StoredKey: storedKey,
			AuthIters: authIters,
		},
	}
}

// parseLegacyUsers разбирает users.json и отвергает всё, что нельзя перенести
// без молчаливой подмены смысла.
//
// Конфликт логинов ВНУТРИ файла — ошибка всегда (§21.4), даже при
// --overwrite-existing: файл, где один логин встречается дважды, не выражает
// намерения оператора, и «побеждает последняя запись» здесь означало бы решить
// за него, какой из двух паролей настоящий. Сегодняшний загрузчик именно так и
// поступает (`internal/auth/userdb.go`), но там это поведение живого файла, а не
// одноразового переноса.
func parseLegacyUsers(data []byte) ([]legacyRecord, error) {
	var ff legacyFile
	if err := json.Unmarshal(data, &ff); err != nil {
		return nil, fmt.Errorf("metadata: parse users.json: %w", err)
	}

	seen := make(map[string]int, len(ff.Users))
	for i, rec := range ff.Users {
		where := fmt.Sprintf("users[%d]", i)
		if err := validateLogin(rec.Login); err != nil {
			return nil, fmt.Errorf("metadata: parse users.json: %s: %w", where, err)
		}
		if prev, dup := seen[rec.Login]; dup {
			return nil, fmt.Errorf(
				"metadata: parse users.json: login %q appears twice (users[%d] and %s); "+
					"the file does not say which record is current, so the migration cannot choose (§21.4)",
				rec.Login, prev, where)
		}
		seen[rec.Login] = i

		// Роль вне словаря отвергается, а не приводится к `user`. Сегодняшний
		// загрузчик молча делает из неизвестной роли `user`; повторить это в
		// миграции значило бы понизить администратора из-за опечатки и не
		// сказать об этом.
		if _, err := domain.ParseRole(rec.Role); err != nil {
			return nil, fmt.Errorf("metadata: parse users.json: %s (login %q): %w", where, rec.Login, err)
		}

		raw, err := hex.DecodeString(rec.StoredKey)
		if err != nil {
			return nil, fmt.Errorf("metadata: parse users.json: %s (login %q): stored_key is not hex: %w",
				where, rec.Login, err)
		}
		if len(raw) != storedKeyLen {
			return nil, fmt.Errorf(
				"metadata: parse users.json: %s (login %q): stored_key is %d bytes, want %d",
				where, rec.Login, len(raw), storedKeyLen)
		}
	}
	return ff.Users, nil
}
