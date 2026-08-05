package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// VerifyInvariants проверяет строки, которые обязаны существовать в ЛЮБОЙ
// инсталляции с первой секунды. Вызывается после миграций и до открытия
// listener.
//
// Проверка нужна именно отдельным шагом, потому что миграции идемпотентны:
// когда версия 1 уже записана, seed не выполняется вовсе, и база, из которой
// строку удалили вручную или неполным восстановлением из backup, поднялась бы
// молча — а отказала бы позже, на первом же запросе, выдавшем page token или
// проверившем пароль.
//
// Ничего не создаётся и не чинится. Для server_secrets это прямое требование
// §6.12: «Отсутствие строки на старте — фатальная ошибка, а не повод
// сгенерировать ключ на лету», потому что молчаливая регенерация обесценила бы
// все выданные page token и сделала бы фиктивные соли AUTH_PARAMS
// недетерминированными между рестартами. Остальные строки чинятся тем же
// способом — восстановлением из backup (§21), а не догадками сервера.
//
// Handle берётся ЧИТАЮЩИЙ: он открыт как mode=ro, поэтому невозможность что-то
// исправить здесь обеспечена механически, а не дисциплиной.
//
// Чего проверка сознательно НЕ делает: не сверяет `users.auth_iters` с
// `auth.pbkdf2_iters` из конфига. §6.2 п. 3 объявляет ошибкой конфигурации
// расхождение значений МЕЖДУ ЗАПИСЯМИ, а не расхождение записи с конфигом;
// оператор, поднявший auth.pbkdf2_iters и пересоздающий пользователей через
// --reset-password, находится в законном состоянии, и отказ старта сломал бы
// ровно этот сценарий. Сверка записей между собой — verifyAuthItersAgreement.
func VerifyInvariants(ctx context.Context, r *sql.DB) error {
	var errs []error
	for _, check := range []func(context.Context, *sql.DB) error{
		verifySystemAccount,
		verifyPublicRoot,
		verifyPublicJournalState,
		verifyServerSecrets,
		verifyAuthItersAgreement,
	} {
		if err := check(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		// Возвращаются ВСЕ расхождения сразу: оператор, восстанавливающий базу,
		// должен увидеть полный список, а не чинить по одному за рестарт.
		return fmt.Errorf("metadata: database invariants violated (restore from backup, §21): %w",
			errors.Join(errs...))
	}
	return nil
}

func verifySystemAccount(ctx context.Context, r *sql.DB) error {
	var (
		login string
		state string
	)
	err := r.QueryRowContext(ctx, `SELECT login, state FROM users WHERE id = ?`,
		int64(domain.SystemUserID)).Scan(&login, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("system account (users.id = %d) is missing (§6.2)", domain.SystemUserID)
	}
	if err != nil {
		return fmt.Errorf("read system account: %w", err)
	}
	if login != domain.SystemLogin {
		return fmt.Errorf("system account login = %q, want %q (§6.2)", login, domain.SystemLogin)
	}
	// §6.2: аккаунт не может пройти аутентификацию ни при каких данных. Его
	// перевод в active означал бы, что кто-то правил таблицу руками.
	if state != string(domain.UserDisabled) {
		return fmt.Errorf("system account state = %q, want %q (§6.2)", state, domain.UserDisabled)
	}
	return nil
}

func verifyPublicRoot(ctx context.Context, r *sql.DB) error {
	var (
		id    string
		owner int64
		kind  string
	)
	err := r.QueryRowContext(ctx, `
SELECT id, owner_user_id, kind FROM resources
WHERE namespace = ? AND id = parent_id AND deleted_at_ms IS NULL`,
		string(domain.NamespacePublic)).Scan(&id, &owner, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("the /public root resource is missing (§6.3)")
	}
	if err != nil {
		return fmt.Errorf("read /public root: %w", err)
	}
	if owner != int64(domain.SystemUserID) {
		return fmt.Errorf("/public root owner_user_id = %d, want %d (§6.3)", owner, domain.SystemUserID)
	}
	if kind != string(domain.KindDir) {
		return fmt.Errorf("/public root kind = %q, want %q (§6.3)", kind, domain.KindDir)
	}
	return nil
}

func verifyPublicJournalState(ctx context.Context, r *sql.DB) error {
	var baselineID string
	err := r.QueryRowContext(ctx, `SELECT baseline_id FROM journal_state WHERE user_id = ?`,
		int64(domain.SystemUserID)).Scan(&baselineID)
	if errors.Is(err, sql.ErrNoRows) {
		// Отсутствие этой строки не выражается ни в одной ошибке во время
		// работы: compaction §14.6 шаг 3 — это UPDATE … WHERE user_id, и на
		// пустой выборке SQLite молча обновляет ноль строк.
		return fmt.Errorf("journal_state row for the /public stream (user_id = %d) is missing (§6.7, §14.6)",
			domain.SystemUserID)
	}
	if err != nil {
		return fmt.Errorf("read /public journal state: %w", err)
	}
	if baselineID == "" {
		return errors.New("journal_state.baseline_id for the /public stream is empty (§14.6)")
	}
	return nil
}

// verifyAuthItersAgreement проверяет §6.2 п. 3: до появления раунда AUTH_PARAMS
// (M14) `users.auth_iters` обязан быть одинаков у ВСЕХ пользователей, и
// расхождение значений между записями отклоняется при старте.
//
// Требование не бюрократическое. Сервер объявляет число итераций в `HELLO_OK`
// ДО того, как узнал логин: логин приходит только в `AUTH_REQUEST` (§3.3).
// Значит, объявлено может быть ровно одно число на всю установку, и
// пользователь, у которого в записи лежит другое, посчитает ClientKey с чужим
// числом итераций и не войдёт НИКОГДА — молча, с обычной ошибкой пароля.
// Отказ старта заменяет этот необъяснимый отказ входа на понятное сообщение.
//
// Учитываются только записи с kdf_algo = 'pbkdf2-sha256': при argon2id колонка
// не используется и хранит 0 (§6.2 п. 4), поэтому её значение сравнивать не с
// чем.
//
// Системный аккаунт из проверки исключён. Его auth_iters проставляет миграция
// из конфига (§6.2) и больше никогда не меняет, а обновить её нечем: команды
// смены пароля у аккаунта, который «не может пройти аутентификацию ни при каких
// данных», нет и быть не должно. Включи его в проверку — и первое же законное
// повышение auth.pbkdf2_iters с пересозданием всех пользователей оставило бы
// демон не поднимающимся навсегда. На вход это значение не влияет ни при каком
// раскладе: системный аккаунт отклоняется до сравнения proof.
func verifyAuthItersAgreement(ctx context.Context, r *sql.DB) error {
	groups, err := authItersGroups(ctx, r)
	if err != nil {
		return err
	}
	if len(groups) <= 1 {
		return nil
	}
	return fmt.Errorf(
		"users.auth_iters differs between records (%s): until the AUTH_PARAMS round of M14 the server "+
			"announces one iteration count in HELLO_OK before it knows the login (§3.3), so users outside "+
			"the majority cannot authenticate at all; re-run the password reset for them or restore the "+
			"previous auth.pbkdf2_iters (§6.2 п. 3)",
		describeAuthIters(groups))
}

// VerifyAuthIters сверяет ДЕЙСТВУЮЩЕЕ число итераций с колонкой
// users.auth_iters всех записей (§6.2 п. 3, §19.4 п. 19).
//
// Проверка отличается от verifyAuthItersAgreement предметом, а не строгостью: та
// сверяет записи между собой, эта — записи с конфигурацией. Одной первой
// недостаточно, и это не теоретическое рассуждение. До раунда AUTH_PARAMS (§3.3)
// клиент выводит ключ по числу итераций из HELLO_OK, то есть по действующему
// auth.pbkdf2_iters, а stored_key посчитан с тем значением, которое лежит в
// колонке. Стоит их развести — и не входит НИ ОДИН пользователь, притом что
// записи между собой согласованы идеально, а сервер отвечает AUTH_FAIL, то есть
// ровно тем же, чем отвечает на неверный пароль. Диагностировать это по логу
// невозможно; поэтому расхождение обязано остановить старт и назвать оба
// значения.
//
// Исключение системного аккаунта — то же и по той же причине, что в
// verifyAuthItersAgreement: его значение проставляет миграция, а пароля, которым
// его можно было бы пересчитать, у него нет.
//
// Метод живёт на репозитории, а не в VerifyInvariants, потому что VerifyInvariants
// проверяет БД саму по себе и конфигурации не видит. Точка контроля — сборка
// сервиса, который это значение использует: не собравшийся UserService не даёт
// демону начать обслуживание, что и требует §19.4 п. 19.
func (us *Users) VerifyAuthIters(ctx context.Context, want int) error {
	if want <= 0 {
		return fmt.Errorf("metadata: auth.pbkdf2_iters = %d, must be > 0", want)
	}
	groups, err := authItersGroups(ctx, us.r)
	if err != nil {
		return err
	}
	// Пустая таблица (кроме системного аккаунта) — обычное состояние свежей
	// установки до --init-admin: сверять не с чем.
	for _, g := range groups {
		if g.iters == int64(want) {
			continue
		}
		return fmt.Errorf(
			"users.auth_iters does not match the configured auth.pbkdf2_iters = %d (%s): before the "+
				"AUTH_PARAMS round of M14 the client derives its key from the value announced in HELLO_OK, "+
				"so nobody can authenticate at all; restore the previous auth.pbkdf2_iters or reset every "+
				"password with `user passwd` (§6.2 п. 3, §19.4 п. 19)",
			want, describeAuthIters(groups))
	}
	return nil
}

// authItersGroup — одно значение auth_iters и записи, которые его держат.
type authItersGroup struct {
	iters       int64
	count       int64
	first, last string
}

// authItersGroups группирует пользователей по auth_iters, по убыванию размера
// группы: первой идёт та, к которой нужно привести остальные.
//
// Помощник общий для двух точек контроля — старта демона и импорта users.json —
// и принимает querier, а не *sql.DB, ровно поэтому: импорт обязан считать
// группы ВНУТРИ своей транзакции, иначе отказ ничего не откатит. Правило
// исключения (только pbkdf2, без системного аккаунта) обязано быть одним и тем
// же в обеих точках, иначе импорт разрешит то, что старт отвергнет.
func authItersGroups(ctx context.Context, q querier) ([]authItersGroup, error) {
	rows, err := q.QueryContext(ctx, `
SELECT auth_iters, count(*), min(login), max(login)
FROM users
WHERE kdf_algo = ? AND id <> ?
GROUP BY auth_iters
ORDER BY count(*) DESC, auth_iters`,
		string(domain.KDFPBKDF2SHA256), int64(domain.SystemUserID))
	if err != nil {
		return nil, fmt.Errorf("read users.auth_iters: %w", err)
	}
	defer rows.Close()

	var groups []authItersGroup
	for rows.Next() {
		var g authItersGroup
		if err := rows.Scan(&g.iters, &g.count, &g.first, &g.last); err != nil {
			return nil, fmt.Errorf("scan users.auth_iters: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read users.auth_iters: %w", err)
	}
	return groups, nil
}

// describeAuthIters печатает группы по-человечески: сообщение обязано называть
// меньшинство поимённо, а не констатировать факт расхождения.
func describeAuthIters(groups []authItersGroup) string {
	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%d iterations: %d user(s), e.g. %q", g.iters, g.count, g.first)
		if g.last != g.first {
			fmt.Fprintf(&b, "…%q", g.last)
		}
	}
	return b.String()
}

// querier — общее у *sql.DB и *sql.Tx. Нужен ровно для того, чтобы проверку
// можно было выполнить и по читающему handle, и внутри открытой транзакции.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func verifyServerSecrets(ctx context.Context, r *sql.DB) error {
	rows, err := r.QueryContext(ctx, `SELECT name, length(value) FROM server_secrets`)
	if err != nil {
		return fmt.Errorf("read server_secrets: %w", err)
	}
	defer rows.Close()

	lengths := make(map[string]int, len(domain.AllSecretNames()))
	for rows.Next() {
		var (
			name   string
			length int
		)
		if err := rows.Scan(&name, &length); err != nil {
			return fmt.Errorf("scan server_secrets: %w", err)
		}
		lengths[name] = length
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read server_secrets: %w", err)
	}

	var errs []error
	for _, name := range domain.AllSecretNames() {
		length, ok := lengths[string(name)]
		if !ok {
			errs = append(errs, fmt.Errorf("server_secrets row %q is missing; it is NOT regenerated on the fly (§6.12)", name))
			continue
		}
		if length != domain.SecretValueLen {
			errs = append(errs, fmt.Errorf("server_secrets row %q holds %d bytes, want %d (§6.12)",
				name, length, domain.SecretValueLen))
		}
	}
	return errors.Join(errs...)
}
