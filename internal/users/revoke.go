package users

import (
	"context"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// operation — административная операция из таблицы §7.4. Имена совпадают с
// командами §7.4 намеренно: строка кода и строка документа должны читаться как
// одна и та же строка.
type operation string

const (
	opDisable operation = "user disable"
	opEnable  operation = "user enable"
	opPasswd  operation = "user passwd"
	opRole    operation = "user role"
	opQuota   operation = "user quota"
	opDelete  operation = "user delete"
	opPurge   operation = "user purge"
)

// sessionAction — колонка «сессии» таблицы §7.4.
type sessionAction uint8

const (
	// sessionsUntouched — прочерк в таблице: сессии не трогаем.
	sessionsUntouched sessionAction = iota
	// sessionsClosed — «закрываются»: немедленно и ВСЕ, включая v2-сессии и
	// активные передачи (§7.4 п. 2).
	sessionsClosed
	// sessionsRecomputed — «пересчёт UserContext»: сессия сохраняется, но роль и
	// квота перечитываются до следующей операции (§7.4 п. 3).
	sessionsRecomputed
)

// revocation — одна строка таблицы «операция → сессии → токены → shares» §7.4.
type revocation struct {
	sessions sessionAction
	// tokens — отзываются ли transfer session tokens (§16.3).
	tokens bool
	// shares — целевое состояние ссылок; пустая строка означает прочерк.
	shares ShareState
}

// revocationTable — таблица §7.4 дословно:
//
//	операция       сессии                токены       shares
//	user disable   закрываются           отзываются   suspended
//	user enable    —                     —            suspended -> active
//	user passwd    закрываются           отзываются   —
//	user role      пересчёт UserContext  отзываются   —
//	user quota     пересчёт UserContext  —            —
//	user delete    закрываются           отзываются   revoked
//	user purge     —                     —            —
//
// Таблица объявлена ДАННЫМИ, а не разложена по телам методов, по двум причинам.
// Во-первых, §7.4 п. 1 фиксирует: решение принято один раз для всей системы и от
// версии протокола не зависит — у такого решения должно быть одно место. Во
// вторых, полнота проверяема: тест обходит перечень операций и падает, если
// какая-то из них не имеет строки или если строка не совпадает с документом.
// Разложенное по семи методам поведение так проверить нельзя — можно только
// перечитать семь методов и поверить.
//
// Строка `user purge` пуста не по недосмотру: к моменту purge пользователь уже
// в pending_delete, его сессии закрыты, токены отозваны, а shares отозваны
// окончательно операцией delete. Отзывать нечего, и §7.4 ставит три прочерка.
var revocationTable = map[operation]revocation{
	opDisable: {sessions: sessionsClosed, tokens: true, shares: ShareSuspended},
	opEnable:  {sessions: sessionsUntouched, tokens: false, shares: ShareActive},
	opPasswd:  {sessions: sessionsClosed, tokens: true},
	opRole:    {sessions: sessionsRecomputed, tokens: true},
	opQuota:   {sessions: sessionsRecomputed},
	opDelete:  {sessions: sessionsClosed, tokens: true, shares: ShareRevoked},
	opPurge:   {},
}

// allOperations — перечень операций §7.4 в порядке таблицы. Нужен тесту
// полноты: без него забытая строка выглядела бы как «операция ничего не
// отзывает», то есть как штатное поведение.
func allOperations() []operation {
	return []operation{opDisable, opEnable, opPasswd, opRole, opQuota, opDelete, opPurge}
}

// applyRevocation приводит живые сессии, токены и ссылки в соответствие с новым
// состоянием пользователя.
//
// Вызывается ПОСЛЕ commit и ДО возврата успеха — именно в этом и состоит
// требование §7.4 («обязана привести … ДО того, как команда вернёт успех»).
// Порядок «состояние → отзыв», а не наоборот, выбран так:
//
//   - отзыв до commit означал бы, что при откате транзакции сессии пользователя
//     всё равно порваны, хотя его состояние не изменилось;
//   - гонки «сессию создали между commit и отзывом» не существует: новая сессия
//     обязана пройти Authenticate, а он читает то же состояние, которое только
//     что зафиксировано. Пользователь, ставший disabled, войти не может; после
//     passwd не подойдёт прежний пароль.
//
// Ошибка означает, что состояние зафиксировано, а отзыв выполнен не полностью, и
// операция обязана вернуть её вместо успеха (§7.4). Отказать может ровно один
// порт — Shares, потому что он пишет в БД; сессии и токены суть состояние
// процесса (см. объявления портов).
//
// Порядок шагов подобран так, что способный отказать порт вызывается ПОСЛЕДНИМ: к
// моменту отказа сессии уже закрыты, а токены отозваны, то есть выполнено всё
// выполнимое. Колонки таблицы §7.4 независимы, и отказ перевода ссылок не причина
// оставить пользователю живые сессии.
func (s *Service) applyRevocation(ctx context.Context, op operation, userID domain.UserID) error {
	row, ok := revocationTable[op]
	if !ok {
		// Недостижимо: операции — константы этого пакета. Паника здесь лучше
		// молчания: пропущенная строка означает неисполненную таблицу §7.4.
		panic("users: operation " + string(op) + " has no row in the §7.4 revocation table")
	}

	// Сессии — первыми: disable, passwd и delete суть реакция на инцидент
	// (§7.4 п. 2), и живой доступ отнимается раньше, чем всё остальное.
	switch row.sessions {
	case sessionsClosed:
		s.sessions.CloseUser(ctx, userID)
	case sessionsRecomputed:
		s.sessions.Recompute(ctx, userID)
	}
	if row.tokens {
		s.tokens.RevokeUser(ctx, userID)
	}
	if row.shares != "" {
		if _, err := s.shares.SetUserShares(ctx, userID, row.shares); err != nil {
			return fmt.Errorf("%w: %s left shares of user %d out of state %q: %w",
				ErrRevocationIncomplete, op, userID, row.shares, err)
		}
	}
	return nil
}

// opForState возвращает операцию §7.4, которой соответствует перевод в state.
// Отображение однозначно: три состояния §6.2 — это ровно три команды §7.4
// (disable, enable, delete), и четвёртой не существует.
func opForState(state domain.UserState) operation {
	switch state {
	case domain.UserActive:
		return opEnable
	case domain.UserDisabled:
		return opDisable
	default:
		return opDelete
	}
}
