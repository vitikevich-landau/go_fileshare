package domain

import "fmt"

// SecretName — имя серверного секрета, колонка `server_secrets.name` (§6.12).
type SecretName string

// Значения SecretName. Перечень закрыт
// CHECK (name IN ('page_token_key','server_secret')).
const (
	// SecretPageTokenKey подписывает page token листинга (§13.3).
	SecretPageTokenKey SecretName = "page_token_key"
	// SecretServerSecret выводит детерминированные фиктивные параметры
	// аутентификации несуществующих логинов (§3.3) и служит корнем для прочих
	// серверных HMAC, которым не нужен отдельный ключ.
	SecretServerSecret SecretName = "server_secret"
)

// SecretValueLen — длина значения секрета в байтах (§6.12,
// CHECK (length(value) = 32)).
const SecretValueLen = 32

// Valid сообщает, входит ли значение в закрытый словарь §6.12.
func (n SecretName) Valid() bool { return n == SecretPageTokenKey || n == SecretServerSecret }

// ParseSecretName разбирает имя секрета, отвергая значения вне словаря §6.12.
func ParseSecretName(s string) (SecretName, error) {
	if v := SecretName(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: secret name %q: want one of %v", s, AllSecretNames())
}

// AllSecretNames возвращает словарь §6.12 целиком, в порядке объявления. Обе
// строки создаются миграцией при инициализации БД: отсутствие строки на старте —
// фатальная ошибка, а не повод сгенерировать ключ на лету (§6.12).
func AllSecretNames() []SecretName { return []SecretName{SecretPageTokenKey, SecretServerSecret} }
