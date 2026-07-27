// Package metadata содержит модель метаданных сервера: схему раздела 6
// docs/tz/10-cloud-drive-spec.md, её forward-only миграции и (начиная с PR2
// M12) репозитории поверх неё.
//
// Разделение с internal/db простое: db отвечает за СОЕДИНЕНИЕ (PRAGMA, пул,
// BEGIN IMMEDIATE, порядок открытия), metadata — за СХЕМУ и работу с данными.
// Драйвер SQLite не импортируется здесь и нигде, кроме internal/db/sqlite.go
// (ADR 0001 §4.6).
package metadata

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

//go:embed schema0001.sql
var schema0001 string

// SeedParams — значения, которые миграция 0001 обязана получить извне, а не
// придумать сама.
type SeedParams struct {
	// AuthIters — auth.pbkdf2_iters из конфига (§19.3). Идёт в строку
	// системного аккаунта, потому что §6.2 п. 3 требует одинакового auth_iters
	// у ВСЕХ записей до появления раунда AUTH_PARAMS в M14, а расхождение между
	// записями считается ошибкой конфигурации и отклоняется при старте.
	// Системный аккаунт — такая же строка users, и исключением он не является.
	AuthIters int
}

// Migrations возвращает полный forward-only список миграций схемы §6.
//
// Список неизменен: применённая миграция никогда не правится, следующее
// изменение схемы — новая версия. Runner (internal/db) отвергает базу, в
// которой применённая версия записана под другим именем.
func Migrations(p SeedParams) []db.Migration {
	return []db.Migration{
		{
			Version: 1,
			Name:    "cloud drive schema",
			Apply: func(ctx context.Context, tx *sql.Tx) error {
				return applySchema0001(ctx, tx, p)
			},
		},
	}
}

// applySchema0001 создаёт схему §6 и наполняет её теми тремя вещами, которые
// §6 требует иметь в ЛЮБОЙ инсталляции с первой же секунды: системным
// аккаунтом, корнем /public и парой серверных секретов.
func applySchema0001(ctx context.Context, tx *sql.Tx, p SeedParams) error {
	if p.AuthIters <= 0 {
		return fmt.Errorf("seed: AuthIters = %d, must be > 0", p.AuthIters)
	}
	if _, err := tx.ExecContext(ctx, schema0001); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if err := seedSystemAccount(ctx, tx, p); err != nil {
		return err
	}
	if err := seedPublicRoot(ctx, tx); err != nil {
		return err
	}
	if err := seedPublicJournalState(ctx, tx); err != nil {
		return err
	}
	return seedServerSecrets(ctx, tx)
}

// seedSystemAccount создаёт запись id = 0, login = 'system' (§6.2). Аккаунт
// создаётся в любой инсталляции, в том числе поднятой с нуля: к импорту
// users.json (§21.4) он отношения не имеет. AUTOINCREMENT выдаёт новым
// пользователям id начиная с 1, поэтому коллизии не возникает.
//
// state = 'disabled' и отдельная проверка «это системный аккаунт», выполняемая
// до сравнения proof, делают вход невозможным. stored_key тем не менее берётся
// из crypto/rand, а не из константы: известное значение — это приглашение
// проверить, действительно ли проверка выполняется раньше сравнения.
func seedSystemAccount(ctx context.Context, tx *sql.Tx, p SeedParams) error {
	storedKey := make([]byte, 32)
	if _, err := rand.Read(storedKey); err != nil {
		return fmt.Errorf("seed system account: random stored_key: %w", err)
	}
	now := int64(domain.NowMillis())
	_, err := tx.ExecContext(ctx, `
INSERT INTO users (id, login, role, state, kdf_algo, salt, stored_key, auth_iters,
                   kdf_params, quota_bytes, used_bytes, reserved_bytes,
                   pending_delete_at_ms, created_at_ms, updated_at_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, 0, NULL, ?, ?)`,
		int64(domain.SystemUserID),
		domain.SystemLogin,
		string(domain.RoleAdmin),
		string(domain.UserDisabled),
		string(domain.KDFPBKDF2SHA256),
		// §6.2 п. 2: до раунда AUTH_PARAMS (M14) соль детерминирована и равна
		// "fileshare-v2:" || login у ВСЕХ записей, включая эту.
		domain.LegacySalt(domain.SystemLogin),
		storedKey,
		p.AuthIters,
		now, now,
	)
	if err != nil {
		return fmt.Errorf("seed system account: %w", err)
	}
	return nil
}

// seedPublicRoot создаёт корень namespace /public (§6.3): id = parent_id,
// пустое name, kind = dir, владелец — системный аккаунт. Корень /home создаётся
// вместе с пользователем и принадлежит ему, поэтому здесь его нет.
//
// Идентификатор случайный, а не константный: он задаёт физические пути (§5.1),
// и предсказуемый корень — предсказуемый путь во всех инсталляциях сразу.
func seedPublicRoot(ctx context.Context, tx *sql.Tx) error {
	id, err := domain.NewResourceID()
	if err != nil {
		return fmt.Errorf("seed public root: %w", err)
	}
	now := int64(domain.NowMillis())
	_, err = tx.ExecContext(ctx, `
INSERT INTO resources (id, owner_user_id, parent_id, namespace, name, name_fold, kind,
                       current_revision, size_bytes, checksum_algo, checksum,
                       created_at_ms, updated_at_ms, deleted_at_ms, trashed_root_id)
VALUES (?, ?, ?, ?, '', '', ?, 0, 0, NULL, NULL, ?, ?, NULL, NULL)`,
		id.String(),
		int64(domain.SystemUserID),
		id.String(),
		string(domain.NamespacePublic),
		string(domain.KindDir),
		now, now,
	)
	if err != nil {
		return fmt.Errorf("seed public root: %w", err)
	}
	return nil
}

// seedPublicJournalState создаёт строку журнального состояния потока /public
// (§6.7, §14.6): «строка journal_state есть у каждого потока; поток /public
// учитывается строкой с user_id = 0». Системный аккаунт заведён в том числе
// ради владения ею (§6.2), поэтому строка создаётся здесь же, а не на этапе
// журнала: собственных потоков у пользователей ещё нет, а поток /public
// существует с первой секунды вместе со своим корнем.
//
// Пропустить её до M17 нельзя не по формальной причине: compaction §14.6
// шаг 3 — это UPDATE … WHERE user_id = :stream. При отсутствующей строке SQLite
// обновит НОЛЬ строк и не сообщит об ошибке, то есть журнал потока молча
// перестанет ужиматься.
//
// Начальные значения нормативны, а не выбраны: §14.6 фиксирует
// «пока compaction не включена, min_retained_seq = 0, и CURSOR_EXPIRED не
// возникает», а baseline_seq = 0 описывает состояние дерева на нулевом seq —
// то есть пустой журнал сразу после установки. Строки этого состояния в
// changes ещё нет, и baseline_id именует именно его.
func seedPublicJournalState(ctx context.Context, tx *sql.Tx) error {
	baselineID, err := domain.NewBaselineID()
	if err != nil {
		return fmt.Errorf("seed public journal state: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO journal_state (user_id, min_retained_seq, baseline_id, baseline_seq,
                           baseline_created_at_ms)
VALUES (?, 0, ?, 0, ?)`,
		int64(domain.SystemUserID), string(baselineID), int64(domain.NowMillis()))
	if err != nil {
		return fmt.Errorf("seed public journal state: %w", err)
	}
	return nil
}

// seedServerSecrets создаёт обе строки §6.12 по 32 байта из crypto/rand.
// Отсутствие строки на старте — фатальная ошибка, а не повод сгенерировать ключ
// на лету: молчаливая регенерация обесценила бы все выданные page token и
// сделала бы фиктивные соли AUTH_PARAMS недетерминированными между рестартами.
func seedServerSecrets(ctx context.Context, tx *sql.Tx) error {
	now := int64(domain.NowMillis())
	for _, name := range domain.AllSecretNames() {
		value := make([]byte, domain.SecretValueLen)
		if _, err := rand.Read(value); err != nil {
			return fmt.Errorf("seed secret %s: %w", name, err)
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_secrets (name, value, created_at_ms, rotated_at_ms)
VALUES (?, ?, ?, NULL)`, string(name), value, now)
		if err != nil {
			return fmt.Errorf("seed secret %s: %w", name, err)
		}
	}
	return nil
}
