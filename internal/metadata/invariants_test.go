package metadata_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// TestVerifyInvariantsOnFreshDatabase — свежая база проходит проверку.
func TestVerifyInvariantsOnFreshDatabase(t *testing.T) {
	d := open(t, t.TempDir())
	if err := metadata.VerifyInvariants(context.Background(), d.Reader); err != nil {
		t.Fatalf("fresh database failed its own invariants: %v", err)
	}
}

// TestVerifyInvariantsCatchesMissingRows — главный сценарий, ради которого
// проверка существует: миграции идемпотентны, поэтому на уже мигрированной базе
// seed не выполняется, и удалённая строка не восстанавливается сама. Без этой
// проверки демон поднялся бы молча и отказал позже — на первом запросе,
// выдавшем page token или проверившем пароль.
func TestVerifyInvariantsCatchesMissingRows(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "нет page_token_key",
			sql:  `DELETE FROM server_secrets WHERE name = 'page_token_key'`,
			want: "page_token_key",
		},
		{
			name: "нет server_secret",
			sql:  `DELETE FROM server_secrets WHERE name = 'server_secret'`,
			want: "server_secret",
		},
		{
			name: "нет строки журнала /public",
			sql:  `DELETE FROM journal_state WHERE user_id = 0`,
			want: "journal_state",
		},
		{
			name: "корень /public помечен удалённым",
			sql: `UPDATE resources SET deleted_at_ms = 1, trashed_root_id = id
			      WHERE namespace = 'public' AND id = parent_id`,
			want: "/public root",
		},
		{
			name: "системный аккаунт включён вручную",
			sql:  `UPDATE users SET state = 'active' WHERE id = 0`,
			want: "system account state",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := open(t, t.TempDir())
			if _, err := d.Writer.ExecContext(ctx, c.sql); err != nil {
				t.Fatalf("break the database: %v", err)
			}
			err := metadata.VerifyInvariants(ctx, d.Reader)
			if err == nil {
				t.Fatal("VerifyInvariants accepted a database with a missing required row")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error must name %q, got: %v", c.want, err)
			}
			// §21: чинится восстановлением из backup, а не сервером. Отдельно
			// проверено, что секрет НЕ сгенерирован заново (§6.12).
			if !strings.Contains(err.Error(), "backup") {
				t.Errorf("error should point at the repair path, got: %v", err)
			}
		})
	}
}

// TestVerifyInvariantsDoesNotRepair — §6.12: отсутствующий секрет не
// восстанавливается на лету. Молчаливая регенерация обесценила бы все выданные
// page token и сделала бы фиктивные соли AUTH_PARAMS недетерминированными между
// рестартами, поэтому «починить» здесь хуже, чем упасть.
func TestVerifyInvariantsDoesNotRepair(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	if _, err := d.Writer.ExecContext(ctx, `DELETE FROM server_secrets`); err != nil {
		t.Fatalf("delete secrets: %v", err)
	}
	if err := metadata.VerifyInvariants(ctx, d.Reader); err == nil {
		t.Fatal("VerifyInvariants accepted a database without server secrets")
	}
	var count int
	if err := d.Reader.QueryRowContext(ctx, `SELECT count(*) FROM server_secrets`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("VerifyInvariants recreated %d secret rows", count)
	}
}

// TestVerifyInvariantsReportsEverythingAtOnce — оператор, восстанавливающий
// базу, должен увидеть полный список расхождений, а не чинить их по одному за
// рестарт.
func TestVerifyInvariantsReportsEverythingAtOnce(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	for _, stmt := range []string{
		`DELETE FROM server_secrets`,
		`DELETE FROM journal_state WHERE user_id = 0`,
	} {
		if _, err := d.Writer.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("break the database: %v", err)
		}
	}
	err := metadata.VerifyInvariants(ctx, d.Reader)
	if err == nil {
		t.Fatal("VerifyInvariants accepted a broken database")
	}
	for _, want := range []string{"page_token_key", "server_secret", "journal_state"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// TestVerifyInvariantsUsesReadOnlyHandle — проверка получает читающий handle,
// поэтому невозможность что-то «исправить» обеспечена механически. Тест
// фиксирует само свойство handle, а не намерение автора.
func TestVerifyInvariantsUsesReadOnlyHandle(t *testing.T) {
	d := open(t, t.TempDir())
	_, err := d.Reader.ExecContext(context.Background(), `DELETE FROM server_secrets`)
	if err == nil {
		t.Fatal("the handle passed to VerifyInvariants can write")
	}
}
