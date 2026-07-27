package domain

import "fmt"

// UserID — стабильный числовой идентификатор пользователя (§2.1). Не зависит от
// логина: смена логина (когда она будет введена) не должна ломать ссылки на
// пользователя.
type UserID int64

// SystemUserID — фиксированный идентификатор системного аккаунта `system`
// (§2.1, §6.2). Аккаунт создаётся миграцией 0001 в любой инсталляции, не может
// пройти аутентификацию ни при каких данных и служит владельцем
// public-ресурсов, переданных при purge их прежнего владельца (§7.4), и
// владельцем строки `journal_state` для потока /public (§6.7).
const SystemUserID UserID = 0

// SystemLogin — логин системного аккаунта (§6.2).
const SystemLogin = "system"

// Role — роль пользователя, колонка `users.role` (§6.2).
type Role string

// Значения Role. Перечень закрыт CHECK (role IN ('user','admin')).
const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.2.
func (r Role) Valid() bool { return r == RoleUser || r == RoleAdmin }

// ParseRole разбирает роль, отвергая значения вне словаря §6.2.
func ParseRole(s string) (Role, error) {
	if r := Role(s); r.Valid() {
		return r, nil
	}
	return "", fmt.Errorf("domain: role %q: want one of %v", s, AllRoles())
}

// AllRoles возвращает словарь §6.2 целиком, в порядке объявления.
func AllRoles() []Role { return []Role{RoleUser, RoleAdmin} }

// UserState — состояние пользователя, колонка `users.state` (§6.2). Булевой
// колонки `enabled` в таблице нет сознательно: флаг и трёхзначное состояние
// §7.4 неизбежно разъезжаются, поэтому источник ровно один.
type UserState string

// Значения UserState. Перечень закрыт
// CHECK (state IN ('active','disabled','pending_delete')).
const (
	// UserActive — вход разрешён.
	UserActive UserState = "active"
	// UserDisabled — вход запрещён, сессии закрыты, shares переведены в
	// `suspended` (§17.4), данные сохраняются.
	UserDisabled UserState = "disabled"
	// UserPendingDelete — вход запрещён, пользователь удалён логически;
	// физический purge выполняется отдельной подтверждённой командой (§7.4).
	// Момент перевода записан в `users.pending_delete_at_ms`, и логин остаётся
	// занятым до purge, иначе новый пользователь унаследует audit-историю
	// старого.
	UserPendingDelete UserState = "pending_delete"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.2.
func (s UserState) Valid() bool {
	switch s {
	case UserActive, UserDisabled, UserPendingDelete:
		return true
	}
	return false
}

// CanAuthenticate сообщает, разрешён ли вход в этом состоянии (§6.2, §7.4).
func (s UserState) CanAuthenticate() bool { return s == UserActive }

// ParseUserState разбирает состояние, отвергая значения вне словаря §6.2.
func ParseUserState(s string) (UserState, error) {
	if v := UserState(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: user state %q: want one of %v", s, AllUserStates())
}

// AllUserStates возвращает словарь §6.2 целиком, в порядке объявления.
func AllUserStates() []UserState {
	return []UserState{UserActive, UserDisabled, UserPendingDelete}
}

// userStateTransitions — ИСЧЕРПЫВАЮЩИЙ перечень допустимых переходов
// `users.state` (§6.2, §7.4). Перечень тестируется §24.1 п. 6.
//
// pending_delete — терминальное состояние: §7.4 делает удаление двухфазным
// (disable → revoke → mark → purge) и обратной команды не вводит. Возврат из
// него был бы не «отменой удаления», а восстановлением учётки, чьи shares уже
// отозваны ОКОНЧАТЕЛЬНО (§17.4) и чьи данные могли быть удалены командой purge:
// пользователь вернулся бы в состояние, которое ничем не отличается от активного,
// но без части своих ресурсов и ссылок.
//
// Перехода «в себя» в перечне нет, потому что это не переход. Идемпотентность
// повторного `user disable` обеспечивает вызывающий, и обеспечивает сознательно:
// повтор обязан заново применить таблицу §7.4, чтобы прерванная на полпути
// операция доводилась повторным запуском.
var userStateTransitions = map[UserState][]UserState{
	UserActive:   {UserDisabled, UserPendingDelete},
	UserDisabled: {UserActive, UserPendingDelete},
}

// CanTransitionUserState сообщает, допустим ли переход from → to по §6.2.
// Переход из терминального состояния не допускается никуда, включая само себя.
func CanTransitionUserState(from, to UserState) bool {
	for _, allowed := range userStateTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// AllowedUserStates возвращает состояния, достижимые из from (§6.2).
func AllowedUserStates(from UserState) []UserState {
	src := userStateTransitions[from]
	out := make([]UserState, len(src))
	copy(out, src)
	return out
}

// KDFAlgo — алгоритм вывода ключа, колонка `users.kdf_algo` (§6.2).
type KDFAlgo string

// Значения KDFAlgo. Перечень закрыт
// CHECK (kdf_algo IN ('pbkdf2-sha256','argon2id')).
const (
	// KDFPBKDF2SHA256 — текущий алгоритм v2-рукопожатия; число итераций лежит в
	// `users.auth_iters`, а `users.kdf_params` равен NULL (§6.2 п. 4).
	KDFPBKDF2SHA256 KDFAlgo = "pbkdf2-sha256"
	// KDFArgon2id — при нём `auth_iters` не используется и хранит 0, а параметры
	// лежат в `kdf_params` в виде `m=<KiB>,t=<iters>,p=<lanes>` (§6.2 п. 4).
	KDFArgon2id KDFAlgo = "argon2id"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.2.
func (a KDFAlgo) Valid() bool { return a == KDFPBKDF2SHA256 || a == KDFArgon2id }

// ParseKDFAlgo разбирает алгоритм, отвергая значения вне словаря §6.2.
func ParseKDFAlgo(s string) (KDFAlgo, error) {
	if a := KDFAlgo(s); a.Valid() {
		return a, nil
	}
	return "", fmt.Errorf("domain: kdf algo %q: want one of %v", s, AllKDFAlgos())
}

// AllKDFAlgos возвращает словарь §6.2 целиком, в порядке объявления.
func AllKDFAlgos() []KDFAlgo { return []KDFAlgo{KDFPBKDF2SHA256, KDFArgon2id} }

// LegacySaltPrefix — префикс детерминированной соли v2 (§6.2 п. 2). До введения
// раунда AUTH_PARAMS (M14) клиент вычисляет соль сам как
// `"fileshare-v2:" || login` (internal/auth/scram.go), поэтому на M12–M13
// сервер обязан хранить именно это значение для ВСЕХ записей, включая вновь
// создаваемые. Смена логина в этот период запрещена: она обесценит stored_key.
const LegacySaltPrefix = "fileshare-v2:"

// LegacySalt возвращает детерминированную соль v2 для логина (§6.2 п. 2).
func LegacySalt(login string) []byte { return []byte(LegacySaltPrefix + login) }

// RandomSaltLen — длина соли после введения раунда AUTH_PARAMS (§6.2 п. 1, M14):
// 16 байт из crypto/rand, не зависящих от логина ни при каком условии.
//
// Значение объявлено до появления самого раунда потому, что от него зависит уже
// сейчас: фиктивная соль несуществующего логина (§3.3 п. 1) обязана быть такой
// же длины, иначе она сама станет признаком «такого пользователя нет».
const RandomSaltLen = 16

// ChallengeLen — длина challenge рукопожатия в байтах (§3.3,
// AuthParamsResponse.Challenge [16]byte).
//
// Объявлено здесь второй раз (первое — proto.ChallengeLen) по причине §4.3 п. 1:
// challenge выдаёт сервисный слой, которому proto недоступен. Совпадение
// проверяется тестом: challenge короче проводного поля уехал бы клиенту
// дополненным нулями, и доказательство считалось бы по другим байтам, чем
// проверялось.
const ChallengeLen = 16
