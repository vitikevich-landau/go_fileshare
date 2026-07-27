package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// UserReference — ссылка на пользователя, которая по §6.11 держит его строку
// действием ON DELETE RESTRICT.
type UserReference struct {
	// Table и Column — где именно лежит ссылка.
	Table, Column string
	// Rows — сколько строк ссылаются.
	Rows int
}

func (r UserReference) String() string {
	return fmt.Sprintf("%s.%s: %d", r.Table, r.Column, r.Rows)
}

// userReferences — перечень колонок, которыми §6.11 связывает объекты с
// пользователем через ON DELETE RESTRICT.
//
// Перечень исчерпывающий и объявлен один раз: ON DELETE CASCADE (journal_state)
// в него не входит по построению, а `changes`, `audit_events` и `blob_gc` внешних
// ключей не имеют вовсе — все три обязаны пережить удаление объектов, о которых
// рассказывают.
//
// resources здесь тоже есть, хотя purge удаляет ресурсы сам: перечень служит
// диагностикой «что именно держит строку», и умалчивать в нём про самую частую
// причину было бы странно.
var userReferences = []struct{ table, column string }{
	{"resources", "owner_user_id"},
	{"uploads", "user_id"},
	{"versions", "owner_user_id"},
	{"trash_entries", "user_id"},
	{"shares", "owner_user_id"},
}

// UserReferences возвращает непустые ссылки на пользователя (§6.11).
//
// Метод существует потому, что RESTRICT сообщает только «FOREIGN KEY
// constraint failed», без имени таблицы: §6.11 требует от purge выполнить работу
// явно и по шагам, а не переложить её на каскад, и вызывающему нужно знать, какой
// именно шаг не выполнен.
func (us *Users) UserReferences(ctx context.Context, tx *sql.Tx, id domain.UserID) ([]UserReference, error) {
	var out []UserReference
	for _, ref := range userReferences {
		var n int
		// Имена таблицы и колонки берутся из перечня выше, а не из аргументов:
		// подставить их в текст запроса можно только так, потому что имя объекта
		// параметром не передаётся.
		query := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = ?`, ref.table, ref.column)
		if err := tx.QueryRowContext(ctx, query, int64(id)).Scan(&n); err != nil {
			return nil, fmt.Errorf("metadata: count %s.%s of user %d: %w", ref.table, ref.column, id, err)
		}
		if n > 0 {
			out = append(out, UserReference{Table: ref.table, Column: ref.column, Rows: n})
		}
	}
	return out, nil
}

// AddUsedBytes изменяет счётчик used_bytes на delta (§11.4).
//
// Метод узкий сознательно: формулы §11.4 принадлежат QuotaService, и репозиторий
// их не воспроизводит. Но одна дельта из исчерпывающей таблицы §11.4 приходится
// на операцию, которая сдаётся РАНЬШЕ QuotaService, — передачу public-ресурсов
// системному аккаунту при purge, — а отложить её нельзя: строка прежнего
// владельца исчезает в той же транзакции вместе со своим used_bytes, и незачтённые
// байты перестают учитываться за кем-либо навсегда.
//
// Отрицательный результат отвергается. Схема его не запрещает, но used_bytes —
// сумма размеров (§11.4), и уход ниже нуля означает не «мало места», а ошибку
// учёта, которую нельзя записывать в базу: дальше она поедет в каждый ответ о
// квоте, а пересчёт §21.3 класс 10 покажет расхождение, не сказав, когда оно
// возникло.
func (us *Users) AddUsedBytes(ctx context.Context, tx *sql.Tx, id domain.UserID, delta int64) error {
	if delta == 0 {
		return nil
	}
	var used int64
	err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM users WHERE id = ?`, int64(id)).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: user %d", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("metadata: read used_bytes of user %d: %w", id, err)
	}
	if used+delta < 0 {
		return fmt.Errorf("metadata: used_bytes of user %d would become %d: used_bytes is a sum of sizes "+
			"and cannot be negative (§11.4)", id, used+delta)
	}
	return execOne(ctx, tx, id, `UPDATE users SET used_bytes = used_bytes + ?, updated_at_ms = ?
WHERE id = ?`, delta, int64(domain.NowMillis()), int64(id))
}

// Delete удаляет строку пользователя (`user purge`, §7.4).
//
// Ссылочную целостность держит схема: RESTRICT на users(id) не даст удалить
// строку, пока существует хоть один ресурс, версия, trash-запись, ссылка или
// загрузка (§6.11). Это намеренно, и метод не пытается обойти правило — порядок
// шагов purge обязан выполнить вызывающий.
//
// journal_state уходит каскадом (§6.11), поэтому отдельного удаления не требует.
func (us *Users) Delete(ctx context.Context, tx *sql.Tx, id domain.UserID) error {
	if id == domain.SystemUserID {
		return fmt.Errorf("%w: %d is the system account (§6.2)", ErrReservedLogin, id)
	}
	return execOne(ctx, tx, id, `DELETE FROM users WHERE id = ?`, int64(id))
}

// Transferred — результат передачи владения: сколько строк переехало и сколько
// байт вместе с ними обязано переехать в счётчик used_bytes приёмника (§11.4).
type Transferred struct {
	Rows int
	// Bytes — сумма size_bytes переданных ФАЙЛОВ, живых и лежащих в корзине:
	// §11.4 считает в used_bytes и то и другое. Каталоги в сумму не входят по
	// построению (CHECK держит их size_bytes нулевым).
	Bytes int64
}

// TransferOwnership переводит ресурсы namespace от одного владельца к другому.
//
// Единственный вызывающий — purge: §7.3 и §7.4 требуют передать public-ресурсы
// удаляемого пользователя системному аккаунту, а не удалять их. Ограничение
// namespace обязательно: тот же UPDATE без него унёс бы и home пользователя,
// то есть отдал бы его личное дерево системному аккаунту вместо удаления.
//
// Байты считаются ДО обновления и возвращаются вызывающему, потому что §11.4
// требует зачесть их приёмнику: квота public-контента списывается с владельца
// (§6.3), а строка прежнего владельца исчезает вместе с его used_bytes, то есть
// незачтённые байты не «потеряются на время» — они перестанут учитываться за кем
// либо навсегда, и обнаружит это только пересчёт §21.3 класс 10 у аккаунта, у
// которого нет ни сессий, ни владельца, способного о нём сообщить.
//
// Версии переданных ресурсов в сумму не входят, хотя §11.4 их называет: их
// перенос — это не только строка `versions`, но и физическое перемещение blob из
// versions/<прежний>/ в versions/<системный>/ (§5.1), а это работа этапа версий.
// До него purge с существующими версиями отклоняется проверкой §6.11
// (Users.UserReferences), поэтому недосчёта здесь возникнуть не может.
func (rs *Resources) TransferOwnership(
	ctx context.Context, tx *sql.Tx, ns domain.Namespace, from, to domain.UserID,
) (Transferred, error) {
	if !ns.Valid() {
		return Transferred{}, fmt.Errorf(
			"metadata: transfer ownership: namespace %q is not in the §6.3 dictionary", ns)
	}

	var bytes sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT sum(size_bytes) FROM resources
WHERE namespace = ? AND owner_user_id = ? AND kind = ?`,
		string(ns), int64(from), string(domain.KindFile)).Scan(&bytes)
	if err != nil {
		return Transferred{}, fmt.Errorf("metadata: sum %s resources of user %d: %w", ns, from, err)
	}

	res, err := tx.ExecContext(ctx, `UPDATE resources SET owner_user_id = ?, updated_at_ms = ?
WHERE namespace = ? AND owner_user_id = ?`,
		int64(to), int64(domain.NowMillis()), string(ns), int64(from))
	if err != nil {
		return Transferred{}, fmt.Errorf("metadata: transfer %s resources of user %d to %d: %w",
			ns, from, to, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Transferred{}, fmt.Errorf("metadata: transfer %s resources of user %d: %w", ns, from, err)
	}
	return Transferred{Rows: int(n), Bytes: bytes.Int64}, nil
}

// DeleteOwned удаляет ВСЕ ресурсы владельца и возвращает их число.
//
// Удаление идёт снизу вверх, потому что RESTRICT на resources.parent_id иначе
// отклонит его (§6.11): за один проход удаляются строки, на которые никто не
// ссылается как на родителя, и проход повторяется, пока такие строки находятся.
// Число проходов ограничено глубиной дерева (§5.3 п. 8), и предел здесь не
// украшение: parent_id способен выразить цикл (испорченная БД, ручная правка), а
// цикл заставил бы цикл while работать вечно, ничего не удаляя.
//
// Родителем считается ссылка ЛЮБОЙ строки, а не только строки того же владельца:
// в namespace public каталог может принадлежать одному пользователю, а файл в нём
// — другому (§6.3), и удалить каталог, пока чужой файл на него ссылается, нельзя.
// Поэтому purge сначала передаёт public-ресурсы системному аккаунту и лишь затем
// удаляет остаток.
//
// Метод НЕ ставит blob в blob_gc и не уменьшает used_bytes — шаги 1–4 §6.11
// принадлежат операциям, которые появятся вместе с загрузками, версиями и
// корзиной. Вызывать его на пользователе, у которого есть такие объекты, нельзя:
// проверку выполняет вызывающий (Users.UserReferences).
func (rs *Resources) DeleteOwned(ctx context.Context, tx *sql.Tx, owner domain.UserID) (int, error) {
	total := 0
	// Пределом служит глубина дерева плюс один проход, за который удаляется
	// корень: глубина считается НИЖЕ корня (§5.3 п. 8). Каждый проход удаляет
	// хотя бы одну строку, иначе цикл прекращается сам.
	for pass := 0; pass <= domain.MaxTreeDepth+1; pass++ {
		res, err := tx.ExecContext(ctx, `DELETE FROM resources
WHERE owner_user_id = ?
  AND id NOT IN (SELECT parent_id FROM resources WHERE parent_id <> id)`, int64(owner))
		if err != nil {
			return total, fmt.Errorf("metadata: delete resources of user %d: %w", owner, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("metadata: delete resources of user %d: %w", owner, err)
		}
		total += int(n)
		if n == 0 {
			break
		}
	}

	// Результат проверяется, а не выводится из того, что проходы закончились.
	// Проход, не удаливший ни строки, означает «листьев не осталось», и это НЕ то
	// же самое, что «строк не осталось»: у цикла parent_id (испорченная БД, ручная
	// правка) листьев нет вовсе, и первый же проход удалил бы ноль строк, а метод
	// вернул бы успех при живом поддереве. Дальше это выглядело бы как
	// необъяснимое «FOREIGN KEY constraint failed» на удалении строки users.
	var left int
	err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM resources WHERE owner_user_id = ?`, int64(owner)).Scan(&left)
	if err != nil {
		return total, fmt.Errorf("metadata: count remaining resources of user %d: %w", owner, err)
	}
	if left > 0 {
		return total, fmt.Errorf("metadata: %d resources of user %d are not deletable bottom-up: "+
			"tree deeper than %d or a parent_id cycle (§5.3 п. 8, §21.3 класс 9)",
			left, owner, domain.MaxTreeDepth)
	}
	return total, nil
}
