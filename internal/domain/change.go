package domain

import "fmt"

// ChangeSeq — глобальный монотонный номер записи журнала изменений (§2.1),
// колонка `changes.seq`. Номер не переиспользуется даже после compaction
// (§14.1).
type ChangeSeq int64

// ChangeOp — операция в журнале изменений, колонка `changes.operation` (§6.7).
// Словарь совпадает один в один с проводным enum ChangeOp* (§14.3).
type ChangeOp string

// Значения ChangeOp. Перечень закрыт CHECK (operation IN (…)) в §6.7. Имён
// `delete` и `restore` в журнале НЕ существует: удаление в корзину пишется как
// trash, восстановление из неё — как restore_trash, окончательное удаление —
// как purge. Второе имя для того же факта запрещено: колонка читается напрямую
// и глазами, и sync-клиентом.
const (
	ChangeCreate         ChangeOp = "create"
	ChangeUpdate         ChangeOp = "update"
	ChangeMkdir          ChangeOp = "mkdir"
	ChangeMove           ChangeOp = "move"
	ChangeTrash          ChangeOp = "trash"
	ChangeRestoreTrash   ChangeOp = "restore_trash"
	ChangePurge          ChangeOp = "purge"
	ChangeVersionRestore ChangeOp = "version_restore"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.7.
func (o ChangeOp) Valid() bool {
	switch o {
	case ChangeCreate, ChangeUpdate, ChangeMkdir, ChangeMove,
		ChangeTrash, ChangeRestoreTrash, ChangePurge, ChangeVersionRestore:
		return true
	}
	return false
}

// ParseChangeOp разбирает операцию, отвергая значения вне словаря §6.7.
func ParseChangeOp(s string) (ChangeOp, error) {
	if o := ChangeOp(s); o.Valid() {
		return o, nil
	}
	return "", fmt.Errorf("domain: change op %q: want one of %v", s, AllChangeOps())
}

// AllChangeOps возвращает словарь §6.7 целиком, в порядке объявления.
func AllChangeOps() []ChangeOp {
	return []ChangeOp{
		ChangeCreate, ChangeUpdate, ChangeMkdir, ChangeMove,
		ChangeTrash, ChangeRestoreTrash, ChangePurge, ChangeVersionRestore,
	}
}
