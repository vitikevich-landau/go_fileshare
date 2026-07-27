package metadata_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// TestSecretsValue — оба секрета §6.12 читаются, различаются между собой и имеют
// нормативную длину.
func TestSecretsValue(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	sec := metadata.NewSecrets(d)

	seen := make(map[string][]byte, len(domain.AllSecretNames()))
	for _, name := range domain.AllSecretNames() {
		value, err := sec.Value(ctx, name)
		if err != nil {
			t.Fatalf("Value(%s): %v", name, err)
		}
		if len(value) != domain.SecretValueLen {
			t.Errorf("Value(%s) вернул %d байт, want %d", name, len(value), domain.SecretValueLen)
		}
		seen[string(name)] = value
	}
	// Один ключ на два назначения означал бы, что подпись page token и фиктивные
	// соли AUTH_PARAMS выводятся из одного корня: ротация одного обесценивала бы
	// другое (§6.12).
	if bytes.Equal(seen[string(domain.SecretPageTokenKey)], seen[string(domain.SecretServerSecret)]) {
		t.Error("page_token_key и server_secret совпали")
	}
}

// TestSecretsValueRejectsUnknownName — перечень §6.12 закрыт CHECK'ом схемы, и
// репозиторий обязан отвергать имя вне словаря сам: иначе опечатка в имени дала
// бы «строки нет» вместо «такого секрета не бывает».
func TestSecretsValueRejectsUnknownName(t *testing.T) {
	sec := metadata.NewSecrets(open(t, t.TempDir()))
	if _, err := sec.Value(context.Background(), domain.SecretName("page-token-key")); err == nil {
		t.Fatal("имя вне словаря §6.12 принято")
	}
}

// TestSecretsValueMissingRowIsAnError — §6.12: отсутствие строки ФАТАЛЬНО и не
// является поводом сгенерировать ключ на лету. Молчаливая регенерация обесценила
// бы все выданные page token и сделала бы фиктивные соли AUTH_PARAMS
// недетерминированными между рестартами, то есть превратила бы сбой в
// незаметное изменение поведения.
func TestSecretsValueMissingRowIsAnError(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())

	err := d.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM server_secrets WHERE name = ?`,
			string(domain.SecretServerSecret))
		return err
	})
	if err != nil {
		t.Fatalf("удаление строки: %v", err)
	}

	_, err = metadata.NewSecrets(d).Value(ctx, domain.SecretServerSecret)
	if !errors.Is(err, metadata.ErrNotFound) {
		t.Fatalf("err = %v, ожидалась обёртка ErrNotFound", err)
	}
}
