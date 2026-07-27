// Package scram — математика SCRAM-подобного рукопожатия challenge–response
// fileshare: цепочка ключей password → SaltedPassword → ClientKey → StoredKey,
// формула ClientProof и её проверка.
//
// Пакет — чистые функции над байтами. Он не знает ни формата кадра, ни таблицы
// users, ни политики выбора соли, и это его единственная причина существовать
// отдельно от internal/auth: §4.3 п. 1 запрещает сервисному пакету зависеть от
// internal/proto, а internal/auth зависит от него ради proto.Role, proto.ProofLen
// и proto.ChecksumLen (§4.3 п. 3). UserService обязан проверять доказательство
// (§27 п. 2) — значит, математика должна быть достижима без wire layout.
//
// Соль здесь ПАРАМЕТР, а не производная от логина. Правило её выбора временное и
// принадлежит вызывающему: до раунда AUTH_PARAMS (§3.3, M14) соль обязана быть
// детерминированной `"fileshare-v2:" || login` (§6.2 п. 2), после — 16 байт из
// crypto/rand. Зашей это правило здесь — и переход на случайные соли стал бы
// правкой в математике, у которой нет причин меняться.
//
// ─── Цепочка ключей ──────────────────────────────────────────────────────────
//
// Все промежуточные значения — 32 байта, но означают РАЗНОЕ. Стрелка «→»
// читается «однонаправленно выводится из» (обратно не развернуть):
//
//	password
//	   │  PBKDF2-HMAC-SHA256(password, salt, iters)
//	   ▼
//	SaltedPassword ──HMAC(·,"Client Key")──▶ ClientKey ──SHA256──▶ StoredKey
//	                                             │                     │
//	                              хранится ТОЛЬКО StoredKey ───────────┘
//	                                     (users.stored_key, §6.2)
//
//	ClientProof = ClientKey XOR HMAC(StoredKey, challenge || login)
//
// Два свойства, ради которых устроено именно так:
//
//  1. пароль НИКОГДА не пересекает сеть — ни открытым текстом, ни хешем;
//  2. кража верификаторов (users.stored_key) НЕ позволяет войти: чтобы подделать
//     ClientProof, нужен ClientKey, а он выводится из пароля, и в базе его нет.
//
// (docs/tz/06-security.md §3, docs/tz/09-go-port.md §5.3.)
package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
)

// KeyLen — длина каждого звена цепочки в байтах. Значение одно для всех звеньев
// потому, что все они — выход SHA-256 или HMAC-SHA-256.
//
// Оно же — длина колонки users.stored_key (§6.2 объявляет её SHA256(ClientKey))
// и длина ClientProof на проводе (proto.ProofLen). Совпадение проверяется
// тестом: разъехавшиеся объявления дали бы обрезанный верификатор, который лёг
// бы в базу молча.
const KeyLen = 32

// Key — одно звено цепочки: SaltedPassword, ClientKey или StoredKey. Отдельных
// типов у них нет сознательно — все три структурно одинаковы, а СМЫСЛ значения
// задаёт имя переменной и функция, которая его вернула.
type Key = [KeyLen]byte

// Proof — ClientProof, доказательство знания пароля, которое клиент помещает в
// AUTH_REQUEST.
type Proof = [KeyLen]byte

const clientKeyLabel = "Client Key"

// SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, dkLen=32) — первое
// звено: «растягивает» пароль, делая перебор дорогим.
func SaltedPassword(password string, salt []byte, iters int) Key {
	dk, err := pbkdf2.Key(sha256.New, password, salt, iters, KeyLen)
	if err != nil {
		// pbkdf2.Key ошибается лишь при некорректной длине ключа, а она тут
		// зафиксирована KeyLen — значит, ветка недостижима.
		panic("scram: pbkdf2: " + err.Error())
	}
	var out Key
	copy(out[:], dk)
	return out
}

// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key"). Это значение и
// подмешивается в доказательство; в базе его НЕТ.
func ClientKey(password string, salt []byte, iters int) Key {
	sp := SaltedPassword(password, salt, iters)
	m := hmac.New(sha256.New, sp[:])
	m.Write([]byte(clientKeyLabel))
	var out Key
	copy(out[:], m.Sum(nil))
	return out
}

// StoredKeyOf возвращает SHA256(ClientKey) — необратимый «отпечаток» ClientKey.
func StoredKeyOf(clientKey Key) Key { return sha256.Sum256(clientKey[:]) }

// StoredKey = SHA256(ClientKey) — верификатор, который хранится в
// users.stored_key (§6.2).
func StoredKey(password string, salt []byte, iters int) Key {
	return StoredKeyOf(ClientKey(password, salt, iters))
}

// authMessage = challenge || login — данные, которые обе стороны подписывают
// StoredKey, чтобы доказательство было привязано и к вызову, и к логину.
func authMessage(challenge []byte, login string) []byte {
	msg := make([]byte, 0, len(challenge)+len(login))
	msg = append(msg, challenge...)
	msg = append(msg, login...)
	return msg
}

// hmacStored = HMAC-SHA256(StoredKey, authMessage). Общий «замок», который умеют
// посчитать обе стороны: клиент — чтобы спрятать ClientKey, сервер — чтобы его
// восстановить.
func hmacStored(storedKey Key, challenge []byte, login string) Key {
	m := hmac.New(sha256.New, storedKey[:])
	m.Write(authMessage(challenge, login))
	var out Key
	copy(out[:], m.Sum(nil))
	return out
}

// xor32 — побайтовый XOR двух звеньев (обратимая «маскировка»:
// a XOR b XOR b == a — на этом и держится восстановление ClientKey в Verify).
func xor32(a, b Key) Key {
	var out Key
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Prove вычисляет ClientProof = ClientKey XOR HMAC-SHA256(StoredKey,
// challenge||login). Именно это клиент кладёт в AUTH_REQUEST: ClientKey
// «замаскирован» замком, который без StoredKey не снять.
func Prove(password string, salt []byte, iters int, challenge []byte, login string) Proof {
	ck := ClientKey(password, salt, iters)
	sk := StoredKeyOf(ck)
	return xor32(ck, hmacStored(sk, challenge, login))
}

// Verify сообщает, аутентифицирует ли proof владельца storedKey для данных
// challenge и login. Идея: сняв тот же замок (XOR с hmacStored), восстанавливаем
// кандидат в ClientKey, берём его SHA256 и сверяем с хранимым StoredKey.
//
// Финальное сравнение — КОНСТАНТНОГО ВРЕМЕНИ, чтобы по длительности нельзя было
// подбирать байты. Функция не знает ни состояния пользователя, ни того, есть ли
// он вообще: проверки «аккаунт отключён» и «это системный аккаунт» выполняются
// ДО обращения сюда (§6.2, §7.4) и здесь не дублируются.
func Verify(storedKey Key, challenge []byte, login string, proof Proof) bool {
	recovered := xor32(proof, hmacStored(storedKey, challenge, login))
	check := StoredKeyOf(recovered)
	return subtle.ConstantTimeCompare(check[:], storedKey[:]) == 1
}
