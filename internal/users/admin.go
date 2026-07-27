package users

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
)

// NewSecret — новый пароль пользователя (§27: SetPassword принимает NewSecret).
//
// Поля Salt здесь НЕТ, и это главное свойство типа. §6.2 п. 1–2 требует, чтобы до
// раунда AUTH_PARAMS (M14) соль оставалась детерминированной
// `"fileshare-v2:" || login`: клиент выводит её сам, и случайная соль сделала бы
// вход невозможным. Правило временное, поэтому репозиторий его не держит (PR2), а
// сервис держит так, чтобы нарушить было НЕЧЕМ: соль вычисляется из логина
// внутри операции, и передать другую невозможно.
//
// AuthIters и KDFAlgo принимаются, хотя выбора не дают. Значение по умолчанию
// (ноль и пустая строка) означает «действующее», а несовпадающее — ошибку
// BAD_REQUEST, как прямо требует §3.3. Молча игнорировать заданное значение
// нельзя: администратор, повысивший число итераций одному пользователю, обязан
// узнать, что этого сделать нельзя, а не обнаружить через месяц, что параметр не
// применился.
type NewSecret struct {
	Password string
	// AuthIters: 0 — действующее значение auth.pbkdf2_iters. Иное значение
	// отклоняется до M14 (§3.3, §6.2 п. 3).
	AuthIters int
	// KDFAlgo: пусто — pbkdf2-sha256. argon2id отклоняется, пока его нечем
	// проверять (§6.2 п. 5).
	KDFAlgo domain.KDFAlgo
}

// CreateUser — данные для `user add` (§7.4).
type CreateUser struct {
	Login string
	Role  domain.Role
	// State допускает active и disabled; пусто означает active. pending_delete —
	// результат `user delete`, а не состояние, в котором заводят учётку (§7.4).
	State  domain.UserState
	Secret NewSecret
	// QuotaBytes = 0 означает unlimited (§6.2).
	QuotaBytes uint64
}

// Create заводит пользователя (`user add`, §7.4).
//
// Вместе со строкой users появляются корень /home и строка journal_state его
// потока — это делает репозиторий в той же транзакции (§6.3, §6.7). Каталога на
// диске здесь не создаётся: файловая система транзакции не имеет, и каталог,
// созданный до commit, остался бы мусором при откате. Его создаёт первая сессия
// (storage.OpenUserHome).
//
// Строки в таблице §7.4 у `user add` нет: отзывать у нового пользователя нечего.
func (s *Service) Create(ctx context.Context, in CreateUser) (User, error) {
	// Роль и состояние проверяет и репозиторий, но класс ошибки важен: §22
	// отображает негодный аргумент в BAD_REQUEST, а необработанную ошибку
	// хранилища граница server обязана считать внутренней.
	if !in.Role.Valid() {
		return User{}, fmt.Errorf("%w: role %q is not in the §6.2 dictionary", ErrBadRequest, in.Role)
	}
	switch in.State {
	case "", domain.UserActive, domain.UserDisabled:
	default:
		return User{}, fmt.Errorf("%w: state %q; a user is created active or disabled, "+
			"pending_delete is the result of `user delete` (§7.4)", ErrBadRequest, in.State)
	}

	secret, err := s.secretFor(in.Login, in.Secret)
	if err != nil {
		return User{}, err
	}
	quota, err := quotaToInt64(in.QuotaBytes)
	if err != nil {
		return User{}, err
	}

	var created metadata.User
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		u, err := s.users.Create(ctx, tx, metadata.NewUser{
			Login:      in.Login,
			Role:       in.Role,
			State:      in.State,
			Secret:     secret,
			QuotaBytes: quota,
		})
		created = u
		return err
	})
	if err != nil {
		return User{}, translate(err)
	}
	return view(created), nil
}

// SetState переводит пользователя в новое состояние: `user disable`,
// `user enable` и первая фаза `user delete` (§7.4).
//
// Три состояния §6.2 — это ровно три команды §7.4, поэтому отдельных методов
// Disable/Enable/Delete нет: они различались бы только константой, а таблица
// отзыва всё равно выбирается по состоянию.
//
// Переход проверяется по §6.2 (domain.CanTransitionUserState): pending_delete
// терминально. Перевод в ТО ЖЕ состояние разрешён и заново применяет таблицу
// §7.4 — так прерванная на полпути операция доводится повторным запуском.
func (s *Service) SetState(ctx context.Context, userID domain.UserID, state domain.UserState) error {
	if userID == domain.SystemUserID {
		return fmt.Errorf("%w: state of the system account is fixed at %q (§6.2)",
			ErrSystemAccount, domain.UserDisabled)
	}
	if !state.Valid() {
		return fmt.Errorf("%w: state %q is not in the §6.2 dictionary", ErrBadRequest, state)
	}

	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		before, err := s.users.ByIDTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if before.State != state && !domain.CanTransitionUserState(before.State, state) {
			return fmt.Errorf("%w: transition %q -> %q is not allowed by §6.2 (allowed: %v)",
				ErrBadRequest, before.State, state, domain.AllowedUserStates(before.State))
		}
		if err := s.users.SetState(ctx, tx, userID, state); err != nil {
			return err
		}
		return s.assertActiveAdminRemains(ctx, tx)
	})
	if err != nil {
		return translate(err)
	}

	return s.applyRevocation(ctx, opForState(state), userID)
}

// SetRole меняет роль (`user role`, §7.4).
//
// Понижение последнего активного администратора отклоняется ErrLastAdminRequired,
// и проверка выполняется В ТОЙ ЖЕ транзакции (§7.4): два параллельных понижения,
// каждое из которых видит двух администраторов, иначе сняли бы обоих.
//
// Запрет «kick самого себя, в том числе до изменения роли» (§7.4,
// docs/tz/05-admin.md §3) здесь ещё НЕ реализован, и место ему именно здесь:
// §27 п. 9 закрепил, что проверка принадлежит сервису, а не границе команды, —
// команд, понижающих собственную роль, больше одной (`user role`,
// `user disable`, `user delete`, deprecated-алиас `--role`), и на границе её
// пришлось бы повторить в каждой. Не хватает единственного: актора, который
// вводится вместе с таблицей audit_events, потому что раньше его принимать
// некому (§27 п. 9, §20.2).
func (s *Service) SetRole(ctx context.Context, userID domain.UserID, role domain.Role) error {
	if userID == domain.SystemUserID {
		return fmt.Errorf("%w: role of the system account is fixed (§6.2)", ErrSystemAccount)
	}
	if !role.Valid() {
		return fmt.Errorf("%w: role %q is not in the §6.2 dictionary", ErrBadRequest, role)
	}

	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if err := s.users.SetRole(ctx, tx, userID, role); err != nil {
			return err
		}
		return s.assertActiveAdminRemains(ctx, tx)
	})
	if err != nil {
		return translate(err)
	}

	// Сессия сохраняется, но обязана перечитать роль до следующей операции, а
	// подписки на админские события снимаются немедленно (§7.4 п. 3–4).
	return s.applyRevocation(ctx, opRole, userID)
}

// SetPassword меняет пароль (`user passwd`, §7.4 п. 6).
//
// Логин читается В транзакции, потому что от него зависит соль (§6.2 п. 2):
// вычислить её заранее, снаружи, значило бы посчитать верификатор для логина,
// который к моменту UPDATE мог оказаться другим.
//
// Сессии закрываются, токены отзываются — passwd отнесён §7.4 п. 2 к реакции на
// инцидент и не ждёт завершения активной передачи.
func (s *Service) SetPassword(ctx context.Context, userID domain.UserID, in NewSecret) error {
	if userID == domain.SystemUserID {
		return fmt.Errorf("%w: the system account has no usable password (§6.2)", ErrSystemAccount)
	}

	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		u, err := s.users.ByIDTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		secret, err := s.secretFor(u.Login, in)
		if err != nil {
			return err
		}
		return s.users.SetSecret(ctx, tx, userID, secret)
	})
	if err != nil {
		return translate(err)
	}

	return s.applyRevocation(ctx, opPasswd, userID)
}

// SetQuota меняет квоту (`user quota`, §7.4). Ноль означает unlimited (§6.2).
//
// Уже выданные reservations не отзываются (§7.4 п. 5): если новая квота меньше
// used_bytes + reserved_bytes, новые резервирования отклоняются QUOTA_EXCEEDED, а
// существующие загрузки доводятся до конца. Поэтому метод не сверяет новое
// значение со счётчиками.
func (s *Service) SetQuota(ctx context.Context, userID domain.UserID, quotaBytes uint64) error {
	if userID == domain.SystemUserID {
		// Системный аккаунт владеет public-ресурсами, переданными при purge их
		// прежних владельцев (§7.3), и §6.2 задаёт ему quota_bytes = 0. Ограничить
		// его квоту значило бы сделать невыполнимой передачу владения.
		return fmt.Errorf("%w: the system account is unlimited by §6.2", ErrSystemAccount)
	}
	quota, err := quotaToInt64(quotaBytes)
	if err != nil {
		return err
	}

	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.users.SetQuota(ctx, tx, userID, quota)
	})
	if err != nil {
		return translate(err)
	}

	// Новая квота применяется к следующему резервированию, поэтому сессия
	// сохраняется и лишь перечитывает UserContext (§7.4 п. 3, п. 5).
	return s.applyRevocation(ctx, opQuota, userID)
}

// Quota возвращает счётчики квоты (§27). Читается на каждый вызов: §27 п. 5
// запрещает кэшировать права и квоту на время сессии, а §7.4 п. 3 требует, чтобы
// новое значение действовало с следующей операции.
func (s *Service) Quota(ctx context.Context, userID domain.UserID) (Quota, error) {
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return Quota{}, translate(err)
	}
	return Quota{
		QuotaBytes:    u.QuotaBytes,
		UsedBytes:     u.UsedBytes,
		ReservedBytes: u.ReservedBytes,
	}, nil
}

// ByID возвращает идентичность пользователя. Нужен там, где сессия обязана
// перечитать пользователя, а не доверять своей копии (§27 п. 5).
func (s *Service) ByID(ctx context.Context, userID domain.UserID) (User, error) {
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return User{}, translate(err)
	}
	return view(u), nil
}

// ByLogin возвращает идентичность пользователя по логину: административные
// команды §7.4 адресуют пользователя логином, а сервис — идентификатором.
func (s *Service) ByLogin(ctx context.Context, login string) (User, error) {
	u, err := s.users.ByLogin(ctx, login)
	if err != nil {
		return User{}, translate(err)
	}
	return view(u), nil
}

// List возвращает всех пользователей (`user list`, §7.4), включая системный
// аккаунт: скрывать его или нет — решение слоя команды, а не сервиса.
func (s *Service) List(ctx context.Context) ([]User, error) {
	rows, err := s.users.List(ctx)
	if err != nil {
		return nil, translate(err)
	}
	out := make([]User, 0, len(rows))
	for _, u := range rows {
		out = append(out, view(u))
	}
	return out, nil
}

// assertActiveAdminRemains проверяет инвариант 13 (§2.2 п. 13, §7.4): в системе
// всегда есть хотя бы один пользователь с ролью admin и состоянием active.
//
// Вызывается ПОСЛЕ изменения строки и в той же транзакции — то есть работает как
// отложенное ограничение: проверяется не «имеет ли право эта операция», а
// «осталось ли множество непустым». Так формулирует инвариант сам §2.2, и так
// исключается расхождение между проверкой и результатом.
//
// Вызывается только из операций, которые МОГУТ сократить множество: SetState,
// SetRole и Purge. Create, SetPassword и SetQuota освобождены не ради экономии
// запроса: на базе, где активного администратора уже нет (испорченная БД, ручная
// правка), проверка в них заблокировала бы восстановительный путь §7.5 —
// `--init-admin --force` создаёт администратора именно в такой ситуации.
func (s *Service) assertActiveAdminRemains(ctx context.Context, tx *sql.Tx) error {
	n, err := s.users.CountActiveAdmins(ctx, tx)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w (§2.2 п. 13, §7.4)", ErrLastAdminRequired)
	}
	return nil
}

// secretFor собирает KDF-материал по правилам §6.2 и §3.3.
//
// Здесь и закрывается долг PR2. Соль — domain.LegacySalt(login), и другой она
// быть не может: §6.2 п. 2 требует хранить ровно это значение у ВСЕХ записей до
// M14, потому что клиент выводит соль сам. Заодно видно, где именно правило
// снимается: в M14 эта функция начинает брать 16 байт из crypto/rand, и больше
// нигде править нечего.
func (s *Service) secretFor(login string, in NewSecret) (metadata.Secret, error) {
	if in.Password == "" {
		return metadata.Secret{}, fmt.Errorf("%w: password is empty", ErrBadRequest)
	}
	algo := in.KDFAlgo
	if algo == "" {
		algo = domain.KDFPBKDF2SHA256
	}
	if algo != domain.KDFPBKDF2SHA256 {
		// argon2id объявлен в §6.2, но проверять доказательство нечем до M14.
		// Завести такую запись значило бы создать пользователя, который не входит
		// ни с каким паролем.
		return metadata.Secret{}, fmt.Errorf("%w: kdf_algo %q has no verifier before M14 (§6.2 п. 5)",
			ErrBadRequest, algo)
	}
	if in.AuthIters != 0 && in.AuthIters != s.authIters {
		// §3.3: `user add` и `user passwd` обязаны отвергать попытку задать иное
		// значение кодом BAD_REQUEST — канала доставки per-user параметров нет до
		// M14, и запись с собственным auth_iters просто не смогла бы войти.
		return metadata.Secret{}, fmt.Errorf(
			"%w: auth_iters = %d, but every record must carry %d until M14 (§6.2 п. 3, §3.3)",
			ErrBadRequest, in.AuthIters, s.authIters)
	}

	salt := domain.LegacySalt(login)
	key := scram.StoredKey(in.Password, salt, s.authIters)
	return metadata.Secret{
		KDFAlgo:   domain.KDFPBKDF2SHA256,
		Salt:      salt,
		StoredKey: key[:],
		AuthIters: s.authIters,
	}, nil
}

// quotaToInt64 переводит квоту из проводного uint64 (§27) в int64 колонки.
// SQLite INTEGER — знаковые 64 бита, поэтому значение выше MaxInt64 не «очень
// большая квота», а отрицательное число в базе.
func quotaToInt64(quotaBytes uint64) (int64, error) {
	if quotaBytes > math.MaxInt64 {
		return 0, fmt.Errorf("%w: quota_bytes = %d exceeds the %d limit of the column",
			ErrBadRequest, quotaBytes, int64(math.MaxInt64))
	}
	return int64(quotaBytes), nil
}
