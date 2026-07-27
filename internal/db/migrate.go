package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// Migration — один forward-only шаг схемы (§6.1). Rollback не предусмотрен: у
// forward-only миграций обратного шага не существует, откат выполняется
// восстановлением из backup (§21).
//
// Apply получает транзакцию, в которой уже выполняется этот шаг; строку в
// schema_migrations пишет сам runner в ТОЙ ЖЕ транзакции. Поэтому «миграция
// применилась наполовину» невозможно: SQLite выполняет DDL транзакционно.
type Migration struct {
	Version int
	Name    string
	Apply   func(ctx context.Context, tx *sql.Tx) error
}

// schemaMigrationsDDL — таблица версий схемы, дословно §6.1.
//
// Её создаёт runner, а не миграция 0001: чтобы узнать, применена ли 0001, нужно
// сначала прочитать эту таблицу. IF NOT EXISTS делает шаг идемпотентным.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
) STRICT;`

// Migrate доводит схему до последней версии из migrations. Вызывается на
// ПИШУЩЕМ handle и до открытия listener (§6.1); повторный вызов на актуальной
// базе — no-op.
//
// Три отказа, которые обязаны быть фатальными, а не молчаливыми:
//
//   - в базе есть версия, которой нет в двоичном файле — база новее демона.
//     Продолжить работу означало бы читать схему, о которой код не знает;
//   - имя уже применённой версии не совпадает с именем в коде — кто-то правил
//     применённую миграцию вместо того, чтобы добавить следующую. Forward-only
//     означает, что применённый шаг неизменен;
//   - версии в списке не строго возрастают — порядок применения неоднозначен.
func Migrate(ctx context.Context, w *sql.DB, migrations []Migration) error {
	if err := validateMigrations(migrations); err != nil {
		return err
	}
	if _, err := w.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("db: create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, w)
	if err != nil {
		return err
	}
	known := make(map[int]string, len(migrations))
	for _, m := range migrations {
		known[m.Version] = m.Name
	}
	for version, name := range applied {
		wantName, ok := known[version]
		if !ok {
			return fmt.Errorf(
				"db: schema version %d (%q) is applied but unknown to this binary: "+
					"the database is newer than the daemon", version, name)
		}
		if wantName != name {
			return fmt.Errorf(
				"db: schema version %d is applied as %q but this binary declares %q: "+
					"an applied forward-only migration must never be edited", version, name, wantName)
		}
	}

	for _, m := range migrations {
		if _, done := applied[m.Version]; done {
			continue
		}
		if err := applyOne(ctx, w, m); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion возвращает наибольшую применённую версию схемы; 0 означает
// пустую базу.
func SchemaVersion(ctx context.Context, h *sql.DB) (int, error) {
	var version sql.NullInt64
	err := h.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("db: read schema version: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

func applyOne(ctx context.Context, w *sql.DB, m Migration) error {
	err := writeTx(ctx, w, func(tx *sql.Tx) error {
		if err := m.Apply(ctx, tx); err != nil {
			return fmt.Errorf("db: migration %04d %q: %w", m.Version, m.Name, err)
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at_ms) VALUES (?, ?, ?)`,
			m.Version, m.Name, int64(domain.NowMillis()))
		if err != nil {
			return fmt.Errorf("db: migration %04d %q: record version: %w", m.Version, m.Name, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func appliedMigrations(ctx context.Context, h *sql.DB) (map[int]string, error) {
	rows, err := h.QueryContext(ctx, `SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("db: read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := make(map[int]string)
	for rows.Next() {
		var (
			version int
			name    string
		)
		if err := rows.Scan(&version, &name); err != nil {
			return nil, fmt.Errorf("db: scan schema_migrations: %w", err)
		}
		out[version] = name
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: read schema_migrations: %w", err)
	}
	return out, nil
}

func validateMigrations(migrations []Migration) error {
	if len(migrations) == 0 {
		return errors.New("db: no migrations declared")
	}
	prev := 0
	for _, m := range migrations {
		if m.Version <= prev {
			return fmt.Errorf("db: migration versions must strictly increase, got %d after %d",
				m.Version, prev)
		}
		if m.Name == "" {
			return fmt.Errorf("db: migration %04d has no name", m.Version)
		}
		if m.Apply == nil {
			return fmt.Errorf("db: migration %04d %q has no Apply", m.Version, m.Name)
		}
		prev = m.Version
	}
	return nil
}
