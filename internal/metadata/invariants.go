package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
// ровно этот сценарий. Сверка записей между собой станет возможна вместе с
// репозиторием пользователей.
func VerifyInvariants(ctx context.Context, r *sql.DB) error {
	var errs []error
	for _, check := range []func(context.Context, *sql.DB) error{
		verifySystemAccount,
		verifyPublicRoot,
		verifyPublicJournalState,
		verifyServerSecrets,
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
