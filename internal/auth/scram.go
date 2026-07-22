// Package auth реализует SCRAM-подобную аутентификацию challenge–response
// fileshare v2. Пароль не пересекает сеть, а кража users.json (в нём лежит лишь
// StoredKey) не позволяет атакующему войти (docs/tz/09-go-port.md §5.3,
// docs/tz/06-security.md §3).
//
// Полная цепочка ключей (password → SaltedPassword → ClientKey → StoredKey),
// формула ClientProof и словарь типов описаны в types.go — прочитайте его, чтобы
// не путать одинаковые по размеру, но разные по смыслу 32-байтные значения.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
)

// DefaultIters — число итераций PBKDF2 по умолчанию для новых пользователей.
// Сервер объявляет действующее значение в HELLO_OK, чтобы клиент вывел ключ с тем
// же параметром. Установлено на порог безопасности из docs/tz/06-security.md §2.
const DefaultIters = 600_000

const clientKeyLabel = "Client Key"

// saltFor возвращает детерминированную соль для логина. Соль привязана к логину,
// поэтому одинаковый пароль у разных пользователей даёт разные ключи.
func saltFor(login Login) []byte {
	return []byte("fileshare-v2:" + login)
}

// saltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, dkLen=32) — первое
// звено цепочки: «растягивает» пароль, делая перебор дорогим.
func saltedPassword(password Password, login Login, iters Iterations) ScramKey {
	dk, err := pbkdf2.Key(sha256.New, password, saltFor(login), iters, 32)
	if err != nil {
		// pbkdf2.Key ошибается лишь при некорректной длине ключа, а она тут
		// зафиксирована в 32 — значит, ветка недостижима.
		panic("auth: pbkdf2: " + err.Error())
	}
	var out [32]byte
	copy(out[:], dk)
	return out
}

// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key"). Это значение и подмешивается
// в доказательство; в базе его НЕТ.
func ClientKey(password Password, login Login, iters Iterations) ScramKey {
	sp := saltedPassword(password, login, iters)
	m := hmac.New(sha256.New, sp[:])
	m.Write([]byte(clientKeyLabel))
	var out ScramKey
	copy(out[:], m.Sum(nil))
	return out
}

// storedKeyFrom возвращает SHA256(ClientKey) — необратимый «отпечаток» ClientKey.
func storedKeyFrom(clientKey ScramKey) ScramKey {
	return sha256.Sum256(clientKey[:])
}

// StoredKey = SHA256(ClientKey) — верификатор, который хранится в users.json.
func StoredKey(password Password, login Login, iters Iterations) ScramKey {
	return storedKeyFrom(ClientKey(password, login, iters))
}

// authMessage = challenge || login — данные, которые обе стороны подписывают
// StoredKey, чтобы доказательство было привязано и к вызову, и к логину.
func authMessage(challenge []byte, login Login) []byte {
	msg := make([]byte, 0, len(challenge)+len(login))
	msg = append(msg, challenge...)
	msg = append(msg, login...)
	return msg
}

// hmacStored = HMAC-SHA256(StoredKey, authMessage). Общий «замок», который умеют
// посчитать обе стороны: клиент — чтобы спрятать ClientKey, сервер — чтобы его
// восстановить.
func hmacStored(storedKey ScramKey, challenge []byte, login Login) ScramKey {
	m := hmac.New(sha256.New, storedKey[:])
	m.Write(authMessage(challenge, login))
	var out ScramKey
	copy(out[:], m.Sum(nil))
	return out
}

// xor32 — побайтовый XOR двух 32-байтных значений (обратимая «маскировка»:
// a XOR b XOR b == a — на этом и держится восстановление ClientKey в Verify).
func xor32(a, b ScramKey) ScramKey {
	var out ScramKey
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Proof вычисляет ClientProof = ClientKey XOR HMAC-SHA256(StoredKey, challenge||login).
// Именно это клиент кладёт в AUTH_REQUEST: ClientKey «замаскирован» замком,
// который без StoredKey не снять.
func Proof(password Password, login Login, iters Iterations, challenge []byte) ClientProof {
	ck := ClientKey(password, login, iters)
	sk := storedKeyFrom(ck)
	return xor32(ck, hmacStored(sk, challenge, login))
}

// Verify сообщает, аутентифицирует ли proof владельца storedKey для данных
// challenge и login. Идея: сняв тот же замок (XOR с hmacStored), восстанавливаем
// кандидат в ClientKey, берём его SHA256 и сверяем с хранимым StoredKey. Финальное
// сравнение — КОНСТАНТНОГО ВРЕМЕНИ, чтобы по длительности нельзя было подбирать байты.
func Verify(storedKey ScramKey, challenge []byte, login Login, proof ClientProof) bool {
	recovered := xor32(proof, hmacStored(storedKey, challenge, login))
	check := storedKeyFrom(recovered)
	return subtle.ConstantTimeCompare(check[:], storedKey[:]) == 1
}
