// Package auth реализует SCRAM-подобную аутентификацию challenge–response
// fileshare v2. Пароль не пересекает сеть, а кража users.json (в нём лежит лишь
// StoredKey) не позволяет атакующему войти (docs/tz/09-go-port.md §5.3,
// docs/tz/06-security.md §3).
//
// Сама математика цепочки ключей живёт в internal/scram — там же её описание,
// вектора и объяснение, почему соль в ней параметр. Здесь остаётся то, что
// математикой не является: v2-политика соли (§6.2 п. 2), users.json и Guard.
//
// Словарь типов пакета — types.go: прочитайте его, чтобы не путать одинаковые по
// размеру, но разные по смыслу 32-байтные значения.
package auth

import (
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
)

// DefaultIters — число итераций PBKDF2 по умолчанию для новых пользователей.
// Сервер объявляет действующее значение в HELLO_OK, чтобы клиент вывел ключ с тем
// же параметром. Установлено на порог безопасности из docs/tz/06-security.md §2.
const DefaultIters = 600_000

// saltFor возвращает детерминированную соль для логина: соль привязана к логину,
// поэтому одинаковый пароль у разных пользователей даёт разные ключи.
//
// Значение берётся у domain.LegacySalt, а не собирается из литерала на месте:
// §6.2 п. 2 требует хранить ровно эту строку в users.salt у ВСЕХ записей, и два
// независимых объявления одной соли — это ровно тот случай, когда расхождение
// проявится не ошибкой сборки, а невозможностью войти после миграции.
//
// Правило временное: с введением раунда AUTH_PARAMS (§3.3, M14) соль становится
// 16 случайными байтами и от логина не зависит вовсе.
func saltFor(login Login) []byte { return domain.LegacySalt(login) }

// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key"). Это значение и подмешивается
// в доказательство; в базе его НЕТ.
func ClientKey(password Password, login Login, iters Iterations) ScramKey {
	return scram.ClientKey(password, saltFor(login), iters)
}

// StoredKey = SHA256(ClientKey) — верификатор, который хранится в users.json.
func StoredKey(password Password, login Login, iters Iterations) ScramKey {
	return scram.StoredKey(password, saltFor(login), iters)
}

// Proof вычисляет ClientProof = ClientKey XOR HMAC-SHA256(StoredKey, challenge||login).
// Именно это клиент кладёт в AUTH_REQUEST: ClientKey «замаскирован» замком,
// который без StoredKey не снять.
func Proof(password Password, login Login, iters Iterations, challenge []byte) ClientProof {
	return scram.Prove(password, saltFor(login), iters, challenge, login)
}

// Verify сообщает, аутентифицирует ли proof владельца storedKey для данных
// challenge и login. Сравнение внутри — константного времени.
func Verify(storedKey ScramKey, challenge []byte, login Login, proof ClientProof) bool {
	return scram.Verify(storedKey, challenge, login, proof)
}
