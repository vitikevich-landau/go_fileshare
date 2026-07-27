package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// ErrLoginExists — логин занят. Занятым он остаётся и у пользователя в состоянии
// pending_delete: §6.2 требует не освобождать логин до purge, иначе новый
// пользователь унаследовал бы audit-историю старого.
var ErrLoginExists = errors.New("metadata: login already exists")

// ErrInvalidLogin — логин не проходит минимальную проверку (см. validateLogin).
var ErrInvalidLogin = errors.New("metadata: invalid login")

// ErrLastAdminRequired — операция опустошила бы множество пользователей с ролью
// admin и состоянием active (§2.2 инвариант 13, §7.4). На границе server
// отображается в код LAST_ADMIN_REQUIRED.
var ErrLastAdminRequired = errors.New("metadata: at least one active administrator is required")

// ErrReservedLogin — логин принадлежит предсозданному системному аккаунту §6.2
// и не может быть занят или перезаписан.
var ErrReservedLogin = errors.New("metadata: login is reserved")

// MaxLoginLen — предел длины логина в байтах.
//
// §6.2 словаря символов логина не задаёт, и это ограничение — не политика, а
// защита от того, что схема выразить не может: логин попадает в детерминированную
// соль `"fileshare-v2:" || login` (§6.2 п. 2), то есть неограниченный логин даёт
// неограниченную соль в каждой строке и в каждом вычислении PBKDF2. Проводной
// предел (proto.MaxStringLen, 64 КиБ) для этой роли не годится. Если §6.2 когда-
// нибудь зафиксирует собственное значение, менять его нужно здесь.
const MaxLoginLen = 255

// User — строка таблицы users (§6.2).
//
// Колонки enabled в структуре нет, как нет её и в схеме: булев флаг и
// трёхзначное состояние §7.4 неизбежно разъезжаются, поэтому единственный
// источник — State.
type User struct {
	ID    domain.UserID
	Login string
	Role  domain.Role
	State domain.UserState

	// Secret — материал проверки пароля. StoredKey — SHA256(ClientKey), из него
	// нельзя ни узнать пароль, ни собрать доказательство.
	Secret Secret

	// QuotaBytes = 0 означает unlimited (§6.2).
	QuotaBytes int64
	// UsedBytes и ReservedBytes определены §11.4; никакая другая часть
	// документа не вправе задавать им иной смысл. Репозиторий их только читает:
	// пишет их арифметика квот (§11.4), приезжающая с QuotaService.
	UsedBytes     int64
	ReservedBytes int64

	// PendingDeleteAt ненулевой ровно тогда, когда State = pending_delete —
	// это выражено CHECK в схеме.
	PendingDeleteAt domain.UnixMillis
	CreatedAt       domain.UnixMillis
	UpdatedAt       domain.UnixMillis
}

// IsSystem сообщает, что это предсозданный системный аккаунт (§6.2). Он не может
// пройти аутентификацию ни при каких данных, и проверка выполняется ДО сравнения
// proof.
func (u User) IsSystem() bool { return u.ID == domain.SystemUserID }

// StoredKeyLen — длина stored_key в байтах. §6.2 определяет колонку как
// SHA256(ClientKey), и это верно при ЛЮБОМ kdf_algo: алгоритм влияет на то, как
// из пароля выводится SaltedPassword, а не на ширину итогового хэша.
//
// Значение продублировано из proto.ChecksumLen сознательно: §4.3 п. 1 запрещает
// metadata импортировать proto.
const StoredKeyLen = 32

// Secret — KDF-материал пользователя: колонки kdf_algo, salt, stored_key,
// auth_iters и kdf_params (§6.2).
type Secret struct {
	KDFAlgo   domain.KDFAlgo
	Salt      []byte
	StoredKey []byte
	// AuthIters — число итераций PBKDF2, с которым посчитан ТЕКУЩИЙ StoredKey.
	// При kdf_algo = argon2id колонка не используется и хранит 0 (§6.2 п. 4).
	AuthIters int
	// KDFParams непуст только при argon2id и имеет вид m=<KiB>,t=<iters>,p=<lanes>;
	// при pbkdf2-sha256 в БД лежит NULL (§6.2 п. 4).
	KDFParams string
}

// NewUser — данные для создания пользователя. Идентификатор не принимается: его
// выдаёт AUTOINCREMENT, начиная с 1, чтобы не столкнуться с системным аккаунтом
// id = 0 (§6.2).
type NewUser struct {
	Login string
	Role  domain.Role
	// State допускает только active и disabled: pending_delete — это результат
	// операции удаления (§7.4), а не состояние, в котором заводят учётку.
	// Пустое значение означает active.
	State      domain.UserState
	Secret     Secret
	QuotaBytes int64
}

// Users — репозиторий таблицы users (§6.2).
//
// Создание пользователя затрагивает три таблицы, поэтому репозиторий знает про
// Resources: у пользователя обязан появиться корень /home (§6.3) и строка
// journal_state его потока (§6.7). Раскладывать это по трём вызовам и надеяться,
// что все три сделает каждый вызывающий, нельзя — пользователь без journal_state
// не проявляется никакой ошибкой во время работы, у него просто молча перестаёт
// ужиматься журнал (§14.6).
type Users struct {
	r   *sql.DB
	res *Resources
}

// NewUsers строит репозиторий поверх открытой пары handle'ов.
func NewUsers(d *db.DB, res *Resources) *Users { return &Users{r: d.Reader, res: res} }

const userColumns = `id, login, role, state, kdf_algo, salt, stored_key, auth_iters,
	kdf_params, quota_bytes, used_bytes, reserved_bytes,
	pending_delete_at_ms, created_at_ms, updated_at_ms`

// ByID возвращает пользователя по идентификатору.
func (us *Users) ByID(ctx context.Context, id domain.UserID) (User, error) {
	row := us.r.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, int64(id))
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: user %d", ErrNotFound, id)
	}
	return u, err
}

// ByLogin возвращает пользователя по логину. Регистр логина значим: сравнение
// побайтовое, как и UNIQUE-индекс схемы.
func (us *Users) ByLogin(ctx context.Context, login string) (User, error) {
	row := us.r.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE login = ?`, login)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: login %q", ErrNotFound, login)
	}
	return u, err
}

// List возвращает всех пользователей, включая системный аккаунт, в порядке
// идентификаторов. Системный аккаунт не скрывается: решение, показывать ли его в
// `user list` (§7.4), принимает слой команды, а не хранилище.
func (us *Users) List(ctx context.Context) ([]User, error) {
	rows, err := us.r.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("metadata: list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metadata: list users: %w", err)
	}
	return out, nil
}

// Create заводит пользователя вместе с корнем /home и строкой journal_state его
// потока — всё в одной переданной транзакции.
//
// Проверка занятости логина выполняется запросом, а не разбором ошибки
// UNIQUE-индекса, по той же причине, что и в Resources.Create: коды драйвера
// видны только в internal/db (ADR 0001 §4.6), а пишущий handle держит одно
// соединение и открывает транзакции как BEGIN IMMEDIATE, поэтому вклиниться
// между проверкой и вставкой некому.
//
// Согласованность auth_iters МЕЖДУ записями (§6.2 п. 3) здесь НЕ проверяется:
// §6.2 объявляет расхождение ошибкой конфигурации, отклоняемой при старте, и
// проверку выполняет VerifyInvariants. Не пустить расхождение в БД заранее —
// работа UserService, который знает действующее значение auth.pbkdf2_iters;
// репозиторий конфига не видит.
func (us *Users) Create(ctx context.Context, tx *sql.Tx, in NewUser) (User, error) {
	if err := validateLogin(in.Login); err != nil {
		return User{}, err
	}
	if !in.Role.Valid() {
		return User{}, fmt.Errorf("metadata: create user %q: role %q is not in the §6.2 dictionary",
			in.Login, in.Role)
	}
	state := in.State
	if state == "" {
		state = domain.UserActive
	}
	switch state {
	case domain.UserActive, domain.UserDisabled:
	default:
		return User{}, fmt.Errorf("metadata: create user %q: state %q; a user is created active or disabled, "+
			"pending_delete is the result of `user delete` (§7.4)", in.Login, state)
	}
	if err := validateSecret(in.Secret); err != nil {
		return User{}, fmt.Errorf("metadata: create user %q: %w", in.Login, err)
	}
	if in.QuotaBytes < 0 {
		return User{}, fmt.Errorf("metadata: create user %q: quota_bytes = %d, must be >= 0 (0 means unlimited)",
			in.Login, in.QuotaBytes)
	}

	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE login = ?`, in.Login).Scan(&exists)
	switch {
	case err == nil:
		return User{}, fmt.Errorf("%w: %q", ErrLoginExists, in.Login)
	case !errors.Is(err, sql.ErrNoRows):
		return User{}, fmt.Errorf("metadata: check login %q: %w", in.Login, err)
	}

	now := domain.NowMillis()
	res, err := tx.ExecContext(ctx, `
INSERT INTO users (login, role, state, kdf_algo, salt, stored_key, auth_iters,
                   kdf_params, quota_bytes, used_bytes, reserved_bytes,
                   pending_delete_at_ms, created_at_ms, updated_at_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?, ?)`,
		in.Login, string(in.Role), string(state), string(in.Secret.KDFAlgo),
		in.Secret.Salt, in.Secret.StoredKey, in.Secret.AuthIters,
		nullableString(in.Secret.KDFParams), in.QuotaBytes, int64(now), int64(now))
	if err != nil {
		return User{}, fmt.Errorf("metadata: create user %q: %w", in.Login, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("metadata: create user %q: read new id: %w", in.Login, err)
	}
	userID := domain.UserID(id)

	// §6.3: корень /home создаётся вместе с пользователем и принадлежит ему.
	if _, err := us.res.CreateRoot(ctx, tx, domain.NamespaceHome, userID); err != nil {
		return User{}, err
	}
	if err := insertJournalState(ctx, tx, userID); err != nil {
		return User{}, fmt.Errorf("metadata: create user %q: %w", in.Login, err)
	}

	return User{
		ID:         userID,
		Login:      in.Login,
		Role:       in.Role,
		State:      state,
		Secret:     in.Secret,
		QuotaBytes: in.QuotaBytes,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// insertJournalState создаёт строку журнального состояния потока пользователя
// (§6.7, §14.6): «строка journal_state есть у каждого потока».
//
// Её отсутствие не выражается ни в одной ошибке во время работы: compaction
// §14.6 шаг 3 — это UPDATE … WHERE user_id, и на пустой выборке SQLite молча
// обновляет ноль строк, то есть журнал потока просто перестаёт ужиматься.
// Поэтому строка создаётся вместе с пользователем, а не на этапе журнала — тем
// же способом, что миграция 0001 создаёт её для потока /public.
//
// Начальные значения нормативны: §14.6 фиксирует «пока compaction не включена,
// min_retained_seq = 0», а baseline_seq = 0 описывает состояние дерева на нулевом
// seq — пустой журнал сразу после создания.
func insertJournalState(ctx context.Context, tx *sql.Tx, userID domain.UserID) error {
	baselineID, err := domain.NewBaselineID()
	if err != nil {
		return fmt.Errorf("journal state: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO journal_state (user_id, min_retained_seq, baseline_id, baseline_seq,
                           baseline_created_at_ms)
VALUES (?, 0, ?, 0, ?)`, int64(userID), string(baselineID), int64(domain.NowMillis()))
	if err != nil {
		return fmt.Errorf("journal state of user %d: %w", userID, err)
	}
	return nil
}

// SetState переводит пользователя в новое состояние, приводя в соответствие
// pending_delete_at_ms: схема требует, чтобы колонка была заполнена РОВНО тогда,
// когда состояние равно pending_delete.
//
// Сессии, токены и shares метод не трогает: таблица «операция → сессии → токены →
// shares» §7.4 — это работа UserService, у которого есть реестр сессий. Repository
// меняет строку, и только её.
func (us *Users) SetState(ctx context.Context, tx *sql.Tx, id domain.UserID, state domain.UserState) error {
	if !state.Valid() {
		return fmt.Errorf("metadata: set state of user %d: %q is not in the §6.2 dictionary", id, state)
	}
	var pendingAt any
	if state == domain.UserPendingDelete {
		pendingAt = int64(domain.NowMillis())
	}
	return execOne(ctx, tx, id, `UPDATE users SET state = ?, pending_delete_at_ms = ?, updated_at_ms = ?
WHERE id = ?`, string(state), pendingAt, int64(domain.NowMillis()), int64(id))
}

// SetRole меняет роль пользователя.
//
// Инвариант последнего администратора (§2.2 п. 13, §7.4) здесь не проверяется:
// он формулируется как «в системе всегда есть активный admin», то есть относится
// ко всей таблице, а не к строке, и проверять его обязан UserService в той же
// транзакции — через CountActiveAdmins.
func (us *Users) SetRole(ctx context.Context, tx *sql.Tx, id domain.UserID, role domain.Role) error {
	if !role.Valid() {
		return fmt.Errorf("metadata: set role of user %d: %q is not in the §6.2 dictionary", id, role)
	}
	return execOne(ctx, tx, id, `UPDATE users SET role = ?, updated_at_ms = ? WHERE id = ?`,
		string(role), int64(domain.NowMillis()), int64(id))
}

// SetQuota меняет квоту. Ноль означает unlimited (§6.2).
//
// Уже выданные reservations не отзываются (§7.4 п. 5): если новая квота меньше
// used_bytes + reserved_bytes, новые резервирования отклоняются QUOTA_EXCEEDED, а
// существующие загрузки доводятся до конца. Поэтому метод не сверяет новое
// значение со счётчиками и не имеет права этого делать.
func (us *Users) SetQuota(ctx context.Context, tx *sql.Tx, id domain.UserID, quotaBytes int64) error {
	if quotaBytes < 0 {
		return fmt.Errorf("metadata: set quota of user %d: %d, must be >= 0 (0 means unlimited)", id, quotaBytes)
	}
	return execOne(ctx, tx, id, `UPDATE users SET quota_bytes = ?, updated_at_ms = ? WHERE id = ?`,
		quotaBytes, int64(domain.NowMillis()), int64(id))
}

// SetSecret записывает новый KDF-материал — то есть смену пароля (§7.4 п. 6).
//
// Соль выбирает вызывающий по правилам §6.2 п. 1–2, а не эта операция: до раунда
// AUTH_PARAMS (M14) она обязана оставаться детерминированной
// `"fileshare-v2:" || login`, потому что клиент выводит её сам, и случайная соль
// сделала бы вход невозможным.
func (us *Users) SetSecret(ctx context.Context, tx *sql.Tx, id domain.UserID, s Secret) error {
	if err := validateSecret(s); err != nil {
		return fmt.Errorf("metadata: set secret of user %d: %w", id, err)
	}
	return execOne(ctx, tx, id, `UPDATE users
SET kdf_algo = ?, salt = ?, stored_key = ?, auth_iters = ?, kdf_params = ?, updated_at_ms = ?
WHERE id = ?`, string(s.KDFAlgo), s.Salt, s.StoredKey, s.AuthIters,
		nullableString(s.KDFParams), int64(domain.NowMillis()), int64(id))
}

// CountActiveAdmins считает пользователей с ролью admin и состоянием active —
// множество, которое инвариант 13 (§2.2, §7.4) запрещает опустошать.
//
// Метод принимает транзакцию, а не ходит в читающий handle, и это существенно:
// §7.4 требует выполнять проверку В ТОЙ ЖЕ транзакции, что и саму операцию, иначе
// два параллельных понижения роли, каждое из которых видит двух администраторов,
// снимут обоих.
//
// Системный аккаунт в счёт не идёт по построению: его состояние — disabled.
func (us *Users) CountActiveAdmins(ctx context.Context, tx *sql.Tx) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = ? AND state = ?`,
		string(domain.RoleAdmin), string(domain.UserActive)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("metadata: count active admins: %w", err)
	}
	return n, nil
}

// execOne выполняет UPDATE одной строки users и превращает «ноль затронутых
// строк» в ErrNotFound: без этого смена роли несуществующего пользователя
// завершилась бы успехом.
func execOne(ctx context.Context, tx *sql.Tx, id domain.UserID, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("metadata: update user %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("metadata: update user %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: user %d", ErrNotFound, id)
	}
	return nil
}

// validateLogin — минимальная проверка, а не политика имён учётных записей:
// §6.2 словаря символов логина не задаёт (см. MaxLoginLen).
//
// Управляющие символы запрещены отдельно от прочего: логин попадает в строки
// аудита (§20.2) и в текстовые логи, и переводом строки внутри логина можно
// подделать соседнюю запись.
func validateLogin(login string) error {
	if login == "" {
		return fmt.Errorf("%w: login is empty", ErrInvalidLogin)
	}
	if !utf8.ValidString(login) {
		return fmt.Errorf("%w: login is not valid UTF-8", ErrInvalidLogin)
	}
	if len(login) > MaxLoginLen {
		return fmt.Errorf("%w: login is %d bytes, limit is %d", ErrInvalidLogin, len(login), MaxLoginLen)
	}
	for _, r := range login {
		if r <= 0x1F || r == 0x7F {
			return fmt.Errorf("%w: login contains control character U+%04X", ErrInvalidLogin, r)
		}
	}
	return nil
}

// validateSecret проверяет связи §6.2 п. 4, которые схема выразить не может: при
// pbkdf2-sha256 kdf_params равен NULL, при argon2id auth_iters хранит 0, а
// параметры лежат в kdf_params.
func validateSecret(s Secret) error {
	if !s.KDFAlgo.Valid() {
		return fmt.Errorf("kdf algo %q is not in the §6.2 dictionary", s.KDFAlgo)
	}
	if len(s.Salt) == 0 {
		return errors.New("salt is empty (§6.2)")
	}
	// Длина проверяется точно, а не «не пусто»: схема ширину BLOB не
	// ограничивает, поэтому короткий верификатор лёг бы в базу молча и дал бы
	// пользователя, который не входит ни с каким паролем.
	if len(s.StoredKey) != StoredKeyLen {
		return fmt.Errorf("stored_key is %d bytes, want %d: the column is SHA256(ClientKey) (§6.2)",
			len(s.StoredKey), StoredKeyLen)
	}
	switch s.KDFAlgo {
	case domain.KDFPBKDF2SHA256:
		if s.AuthIters <= 0 {
			return fmt.Errorf("auth_iters = %d for pbkdf2-sha256, must be > 0 (§6.2 п. 4)", s.AuthIters)
		}
		if s.KDFParams != "" {
			return fmt.Errorf("kdf_params = %q for pbkdf2-sha256, must be empty (§6.2 п. 4)", s.KDFParams)
		}
	case domain.KDFArgon2id:
		if s.AuthIters != 0 {
			return fmt.Errorf("auth_iters = %d for argon2id, must be 0 (§6.2 п. 4)", s.AuthIters)
		}
		// Форма строки (m=<KiB>,t=<iters>,p=<lanes>) проверяется вместе с
		// поддержкой argon2id: разбирать параметры, которыми никто не считает
		// ключ, значило бы объявить формат раньше его единственного потребителя.
		if s.KDFParams == "" {
			return errors.New("kdf_params is empty for argon2id (§6.2 п. 4)")
		}
	}
	return nil
}

func scanUser(s scanner) (User, error) {
	var (
		u          User
		id         int64
		role       string
		state      string
		kdfAlgo    string
		kdfParams  sql.NullString
		pendingAt  sql.NullInt64
		created    int64
		updated    int64
		authIters  int64
		quotaBytes int64
	)
	err := s.Scan(&id, &u.Login, &role, &state, &kdfAlgo, &u.Secret.Salt, &u.Secret.StoredKey,
		&authIters, &kdfParams, &quotaBytes, &u.UsedBytes, &u.ReservedBytes,
		&pendingAt, &created, &updated)
	if err != nil {
		return User{}, err
	}

	if u.Role, err = domain.ParseRole(role); err != nil {
		return User{}, fmt.Errorf("metadata: users.role of %d: %w", id, err)
	}
	if u.State, err = domain.ParseUserState(state); err != nil {
		return User{}, fmt.Errorf("metadata: users.state of %d: %w", id, err)
	}
	if u.Secret.KDFAlgo, err = domain.ParseKDFAlgo(kdfAlgo); err != nil {
		return User{}, fmt.Errorf("metadata: users.kdf_algo of %d: %w", id, err)
	}
	u.ID = domain.UserID(id)
	u.Secret.AuthIters = int(authIters)
	u.Secret.KDFParams = kdfParams.String
	u.QuotaBytes = quotaBytes
	u.CreatedAt = domain.UnixMillis(created)
	u.UpdatedAt = domain.UnixMillis(updated)
	if pendingAt.Valid {
		u.PendingDeleteAt = domain.UnixMillis(pendingAt.Int64)
	}
	return u, nil
}

// nullableString отображает пустую строку в NULL: §6.2 требует NULL в
// kdf_params при pbkdf2-sha256, а пустая строка — это не NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
