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

// legacyFile — формат users.json (`{"users": [...]}`), из которого §21.4 берёт
// пользователей.
//
// Структура объявлена здесь, а не переиспользована из internal/auth, по той же
// причине, что и StoredKeyLen: auth импортирует proto. Формат заморожен — это
// вход одноразовой миграции, а не живая модель, — поэтому дублирование четырёх
// полей дешевле нарушения правила зависимостей.
type legacyFile struct {
	// Указатель, чтобы отличить ОТСУТСТВУЮЩИЙ ключ от пустого массива: у
	// значения-слайса оба случая дают nil.
	Users *[]legacyRecord `json:"users"`
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
	// NoActiveAdmin сообщает, что в получившейся базе нет ни одного
	// пользователя с ролью admin и состоянием active. Это не ошибка импорта
	// (см. ImportUsers), но daemon с такой базой не стартует (§7.5), поэтому
	// команда обязана сказать об этом вслух.
	NoActiveAdmin bool
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
//
// Инвариант последнего администратора (§2.2 п. 13) применяется ровно в той
// форме, в какой его задаёт §7.4: отклоняются операции, которые СДЕЛАЛИ БЫ
// множество активных администраторов пустым. Импорт, после которого админов не
// осталось, хотя до него они были, — это оно и есть, и он отклоняется.
//
// А вот импорт в базу, где активных администраторов не было И ДО него,
// проходит: множество пустым делает не он. Отказ в этом случае был бы прямо
// вреден — восстановительный путь §7.5 это `fshare-daemon --promote <login>`,
// то есть повышение УЖЕ ИМПОРТИРОВАННОГО пользователя, и запрет на импорт
// сделал бы его невыполнимым. Оператор получил бы файл, который некуда залить,
// и базу, которую некем починить. Вместо отказа поднимается флаг
// ImportReport.NoActiveAdmin, о котором команда сообщает вслух.
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
		adminsBefore, err := us.CountActiveAdmins(ctx, tx)
		if err != nil {
			return err
		}
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
		// Счёт снимается в ТОЙ ЖЕ транзакции, что и записи: иначе отказ уже
		// ничего не откатил бы.
		adminsAfter, err := us.CountActiveAdmins(ctx, tx)
		if err != nil {
			return err
		}
		if adminsAfter == 0 && adminsBefore > 0 {
			return fmt.Errorf(
				"metadata: import users: the import would leave the database without an active administrator "+
					"(%d before, 0 after): %w; keep at least one record with role \"admin\" and \"enabled\": true "+
					"in the JSON (§2.2 инвариант 13, §7.4)",
				adminsBefore, ErrLastAdminRequired)
		}
		rep.NoActiveAdmin = adminsAfter == 0

		// §6.2 п. 3 проверяется здесь же, а не оставляется старту демона.
		//
		// Расхождение возникает буднично: в базе лежат пользователи, посчитанные
		// со старым auth.pbkdf2_iters, конфиг с тех пор подняли, и импорт того же
		// файла пропускает их как идентичные (auth_iters не входит в сверку
		// §21.4), а новую запись создаёт уже с новым значением. Команда
		// отрапортовала бы об успехе, демон не поднялся бы, и — что хуже всего —
		// повторный импорт этого уже не чинит: пропуск остаётся пропуском.
		//
		// Отказ здесь и означает, что миграцию запустили с конфигом, который не
		// соответствует переносимому файлу.
		groups, err := authItersGroups(ctx, tx)
		if err != nil {
			return fmt.Errorf("metadata: import users: %w", err)
		}
		if len(groups) > 1 {
			return fmt.Errorf(
				"metadata: import users: the result would hold more than one PBKDF2 iteration count (%s); "+
					"auth.pbkdf2_iters is %d now, but the stored keys already in the database were computed "+
					"with another value, and a re-run cannot repair this because identical records are skipped "+
					"by design (§21.4). Run the import with the auth.pbkdf2_iters that produced the JSON, or "+
					"reset the passwords of the minority (§6.2 п. 3)",
				describeAuthIters(groups), opts.AuthIters)
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
	if len(diff.fields) == 0 {
		return actionSkipped, nil
	}
	if !opts.OverwriteExisting {
		return 0, fmt.Errorf(
			"metadata: import user %q: the database already holds this login with different data (%s); "+
				"re-run with --overwrite-existing to replace the record with the values from the JSON (§21.4)",
			rec.Login, strings.Join(diff.fields, ", "))
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
	// Секрет переписывается ТОЛЬКО когда он и правда изменился. Иначе
	// перезапись роли или состояния протащила бы в запись auth_iters из
	// сегодняшнего конфига, оставив прежний stored_key, — то есть ровно то
	// расхождение, ради недопущения которого auth_iters исключён из сверки
	// выше. Пользователь после этого не вошёл бы вовсе, а следующий старт
	// демона упёрся бы в проверку §6.2 п. 3.
	if diff.secret {
		if err := us.SetSecret(ctx, tx, id, want.Secret); err != nil {
			return 0, err
		}
	}
	return actionUpdated, nil
}

// recordDiff — что именно разошлось между записью в БД и записью в файле.
type recordDiff struct {
	// fields перечисляет расхождения по-человечески: §21.4 требует «понятной
	// ошибки с указанием логина и различающихся полей», а не констатации факта.
	fields []string
	// secret сообщает, что разошлось хотя бы одно поле KDF-материала. От него
	// зависит, трогать ли auth_iters.
	secret bool
}

// diffFields сравнивает запись файла с записью БД. Значения секрета в
// сообщение не попадают: stored_key — это верификатор пароля, и его место не в
// логе оператора.
func diffFields(want NewUser, role, state, kdfAlgo string, salt, storedKey []byte) recordDiff {
	var d recordDiff
	if role != string(want.Role) {
		d.fields = append(d.fields, fmt.Sprintf("role: %q in the database, %q in the JSON", role, want.Role))
	}
	if state != string(want.State) {
		d.fields = append(d.fields, fmt.Sprintf("state: %q in the database, %q in the JSON", state, want.State))
	}
	if kdfAlgo != string(want.Secret.KDFAlgo) {
		d.fields = append(d.fields, fmt.Sprintf("kdf_algo: %q in the database, %q in the JSON",
			kdfAlgo, want.Secret.KDFAlgo))
		d.secret = true
	}
	if string(salt) != string(want.Secret.Salt) {
		d.fields = append(d.fields, "salt")
		d.secret = true
	}
	if string(storedKey) != string(want.Secret.StoredKey) {
		d.fields = append(d.fields, "stored_key")
		d.secret = true
	}
	return d
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

// renameAdvice — что делать оператору с записью, чей логин перенести нельзя.
//
// Совет обязан называть ОБА действия. Соль до раунда AUTH_PARAMS (M14)
// детерминирована и равна `"fileshare-v2:" || login` (§6.2 п. 2), поэтому
// stored_key привязан к логину: под новым логином клиент выведет ClientKey с
// другой солью, и прежний верификатор ему не подойдёт. Совет «переименуйте
// запись» без второй половины дал бы успешный импорт и учётку, которая не
// пускает по своему же паролю, — то есть ровно тот молчаливый отказ входа, от
// которого спасает вся остальная работа этого файла. По той же причине §7.4 не
// предоставляет команды `user rename` до перехода на случайные соли.
const renameAdvice = "such a record cannot be migrated as it is: rename it in the JSON AND reset its " +
	"password afterwards — stored_key is bound to the login through the salt \"fileshare-v2:\"||login " +
	"(§6.2 п. 2), so a renamed account cannot authenticate with the old password"

// parseLegacyUsers разбирает users.json и отвергает всё, что нельзя перенести
// без молчаливой подмены смысла.
//
// Найденное сообщается ЦЕЛИКОМ, а не по одной находке за запуск: импорт всё
// равно всё или ничего, и оператор, правящий файл, должен увидеть полный список
// записей, требующих внимания, — тем же способом, что и VerifyInvariants.
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
	// Отсутствие ключа `users` — ошибка, а не пустой файл. Опечатка вроде
	// `{"user":[…]}` разбирается без единой жалобы и даёт ноль записей, то есть
	// одноразовая миграция отрапортовала бы об успехе и оставила базу пустой.
	// Осознанно пустой массив при этом остаётся законным: `auth.Save` пишет
	// `{"users":[]}`, когда пользователей не осталось.
	if ff.Users == nil {
		return nil, errors.New(`metadata: parse users.json: no top-level "users" array; ` +
			`an empty import is spelled {"users": []}`)
	}

	users := *ff.Users
	seen := make(map[string]int, len(users))
	var problems []error
	for i, rec := range users {
		where := fmt.Sprintf("users[%d]", i)

		// Правила логина — MaxLoginLen и запрет управляющих символов — введены
		// вместе с новой моделью, и старый файл о них не знал: `--add-user`
		// пишет в users.json любую непустую строку, а загрузчик её принимает.
		// Значит, такая учётка могла годами работать и входить. Перенести её как
		// есть всё равно нельзя (логин уходит в соль и в записи аудита §20.2),
		// поэтому отказ остаётся — но сопровождается выполнимым указанием, а не
		// одной констатацией.
		if err := validateLogin(rec.Login); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w; %s", where, err, renameAdvice))
			continue
		}
		// Логин `system` в старом файле совершенно легален — резервирует его
		// только §6.2, которого во времена users.json не существовало. Но в
		// новой схеме он принадлежит предсозданной записи id = 0, и импорт
		// поверх неё ломает установку необратимо: с --overwrite-existing запись
		// получила бы role, state и секрет из JSON, а обычная (enabled) учётка
		// перевела бы системный аккаунт в active — после чего verifySystemAccount
		// не пускает demon стартовать, и починить это можно только правкой БД
		// руками. Поэтому отказ, а не пропуск записи: пропустив, мы потеряли бы
		// пользователя молча.
		if rec.Login == domain.SystemLogin {
			problems = append(problems, fmt.Errorf(
				"%s: login %q is reserved for the pre-seeded system account (§6.2): %w; %s",
				where, rec.Login, ErrReservedLogin, renameAdvice))
			continue
		}
		if prev, dup := seen[rec.Login]; dup {
			problems = append(problems, fmt.Errorf(
				"login %q appears twice (users[%d] and %s); "+
					"the file does not say which record is current, so the migration cannot choose (§21.4)",
				rec.Login, prev, where))
			continue
		}
		seen[rec.Login] = i

		// Роль вне словаря отвергается, а не приводится к `user`. Сегодняшний
		// загрузчик молча делает из неизвестной роли `user`; повторить это в
		// миграции значило бы понизить администратора из-за опечатки и не
		// сказать об этом.
		if _, err := domain.ParseRole(rec.Role); err != nil {
			problems = append(problems, fmt.Errorf("%s (login %q): %w", where, rec.Login, err))
		}

		raw, err := hex.DecodeString(rec.StoredKey)
		switch {
		case err != nil:
			problems = append(problems, fmt.Errorf("%s (login %q): stored_key is not hex: %w",
				where, rec.Login, err))
		case len(raw) != StoredKeyLen:
			problems = append(problems, fmt.Errorf("%s (login %q): stored_key is %d bytes, want %d",
				where, rec.Login, len(raw), StoredKeyLen))
		}
	}
	if len(problems) != 0 {
		return nil, fmt.Errorf("metadata: parse users.json: %w", errors.Join(problems...))
	}
	return users, nil
}
