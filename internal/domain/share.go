package domain

import "fmt"

// ShareState — состояние публичной ссылки, колонка `shares.state` (§6.8).
type ShareState string

// Значения ShareState. Перечень закрыт
// CHECK (state IN ('active','suspended','revoked')).
const (
	// ShareActive — ссылка работает, пока не истёк expires_at_ms.
	ShareActive ShareState = "active"
	// ShareSuspended — обратимое состояние: перевод пользователя в disabled
	// переводит все его ссылки сюда, обратное включение возвращает их в active
	// (§17.4).
	ShareSuspended ShareState = "suspended"
	// ShareRevoked — необратимо.
	ShareRevoked ShareState = "revoked"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.8.
func (s ShareState) Valid() bool {
	switch s {
	case ShareActive, ShareSuspended, ShareRevoked:
		return true
	}
	return false
}

// ParseShareState разбирает состояние, отвергая значения вне словаря §6.8.
func ParseShareState(s string) (ShareState, error) {
	if v := ShareState(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: share state %q: want one of %v", s, AllShareStates())
}

// AllShareStates возвращает словарь §6.8 целиком, в порядке объявления.
func AllShareStates() []ShareState { return []ShareState{ShareActive, ShareSuspended, ShareRevoked} }
