package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// Secrets — репозиторий таблицы server_secrets (§6.12).
//
// Только чтение. Строки создаёт миграция 0001, а заменяет их локальная команда
// остановленного daemon `--rotate-secret` (§6.12): метода «создать секрет» здесь
// нет намеренно, потому что молчаливая регенерация обесценила бы все выданные
// page token и сделала бы фиктивные соли AUTH_PARAMS недетерминированными между
// рестартами.
type Secrets struct {
	r *sql.DB
}

// NewSecrets строит репозиторий поверх открытой пары handle'ов.
func NewSecrets(d *db.DB) *Secrets { return &Secrets{r: d.Reader} }

// Value возвращает значение секрета.
//
// Отсутствие строки — ошибка, а не пустое значение: §6.12 объявляет её
// ФАТАЛЬНОЙ. Ошибка не содержит самого значения и содержать не вправе — §6.12
// запрещает писать его в лог, в audit, в метрики и в отчёты fsck, а текст ошибки
// доезжает до всех четырёх.
func (s *Secrets) Value(ctx context.Context, name domain.SecretName) ([]byte, error) {
	if !name.Valid() {
		return nil, fmt.Errorf("metadata: secret %q is not in the §6.12 dictionary", name)
	}
	var value []byte
	err := s.r.QueryRowContext(ctx,
		`SELECT value FROM server_secrets WHERE name = ?`, string(name)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: server secret %q; it is NOT generated on the fly (§6.12)",
			ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("metadata: read server secret %q: %w", name, err)
	}
	// Длина проверяется, хотя её держит CHECK схемы: секрет короче ожидаемого
	// ослабил бы каждый HMAC, который им подписан, и заметить это по поведению
	// невозможно — подписи продолжают сходиться сами с собой.
	if len(value) != domain.SecretValueLen {
		return nil, fmt.Errorf("metadata: server secret %q holds %d bytes, want %d (§6.12)",
			name, len(value), domain.SecretValueLen)
	}
	return value, nil
}
