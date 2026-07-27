package domain

import "fmt"

// UploadState — состояние незавершённой загрузки, колонка `uploads.state`
// (§6.4). Состояние загрузки хранится ТОЛЬКО в SQLite; второго источника истины
// о загрузке нет (§2.1).
type UploadState string

// Значения UploadState. Перечень закрыт CHECK (state IN (…)) в §6.4.
const (
	UploadCreated    UploadState = "created"
	UploadReceiving  UploadState = "receiving"
	UploadVerifying  UploadState = "verifying"
	UploadCommitting UploadState = "committing"
	UploadCompleted  UploadState = "completed"
	UploadCancelled  UploadState = "cancelled"
	UploadFailed     UploadState = "failed"
	UploadExpired    UploadState = "expired"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.4.
func (s UploadState) Valid() bool {
	switch s {
	case UploadCreated, UploadReceiving, UploadVerifying, UploadCommitting,
		UploadCompleted, UploadCancelled, UploadFailed, UploadExpired:
		return true
	}
	return false
}

// IsTerminal сообщает, что состояние необратимо (§6.4). Терминальные состояния
// исключены из частичных уникальных индексов `uploads_client_key` и
// `uploads_active_target`, поэтому клиент вправе переиспользовать
// ClientUploadKey и то же целевое имя после cancelled/failed/expired.
func (s UploadState) IsTerminal() bool {
	switch s {
	case UploadCompleted, UploadCancelled, UploadFailed, UploadExpired:
		return true
	}
	return false
}

// ParseUploadState разбирает состояние, отвергая значения вне словаря §6.4.
func ParseUploadState(s string) (UploadState, error) {
	if v := UploadState(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: upload state %q: want one of %v", s, AllUploadStates())
}

// AllUploadStates возвращает словарь §6.4 целиком, в порядке объявления.
func AllUploadStates() []UploadState {
	return []UploadState{
		UploadCreated, UploadReceiving, UploadVerifying, UploadCommitting,
		UploadCompleted, UploadCancelled, UploadFailed, UploadExpired,
	}
}

// ActiveUploadStates — нетерминальные состояния (§6.4). Ровно этим перечнем
// заданы предикаты частичных уникальных индексов `uploads_client_key` и
// `uploads_active_target` в миграции 0001, поэтому перечень объявлен один раз и
// сверяется с DDL тестом.
func ActiveUploadStates() []UploadState {
	return []UploadState{UploadCreated, UploadReceiving, UploadVerifying, UploadCommitting}
}

// uploadTransitions — ИСЧЕРПЫВАЮЩИЙ перечень допустимых переходов §6.4.
// Обратные переходы существуют не для красоты: verifying → receiving требует
// §8.4 (размер staging меньше expected_size_bytes, OFFSET_MISMATCH), а
// verifying/committing → receiving — §5.5 (после рестарта живого recovery
// marker нет). Перечень тестируется §24.1 п. 6.
var uploadTransitions = map[UploadState][]UploadState{
	UploadCreated:    {UploadReceiving, UploadCancelled, UploadExpired, UploadFailed},
	UploadReceiving:  {UploadVerifying, UploadCancelled, UploadExpired, UploadFailed},
	UploadVerifying:  {UploadCommitting, UploadReceiving, UploadCancelled, UploadExpired, UploadFailed},
	UploadCommitting: {UploadCompleted, UploadReceiving, UploadCancelled, UploadExpired, UploadFailed},
}

// CanTransition сообщает, допустим ли переход from → to по §6.4. Переход из
// терминального состояния не допускается никуда, включая само себя.
func CanTransition(from, to UploadState) bool {
	for _, allowed := range uploadTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// AllowedTransitions возвращает состояния, достижимые из from (§6.4).
func AllowedTransitions(from UploadState) []UploadState {
	src := uploadTransitions[from]
	out := make([]UploadState, len(src))
	copy(out, src)
	return out
}

// OverwriteMode — поведение при существующей цели, колонка
// `uploads.overwrite_mode` (§6.4). Повторяет проводной enum OverwriteMode
// (§8.1) и закрыт теми же двумя значениями: режима `rename` у загрузок нет —
// выбор безопасного имени существует только у restore из корзины (§10.2).
type OverwriteMode string

// Значения OverwriteMode. Перечень закрыт
// CHECK (overwrite_mode IN ('fail','overwrite')).
const (
	OverwriteFail      OverwriteMode = "fail"
	OverwriteOverwrite OverwriteMode = "overwrite"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.4.
func (m OverwriteMode) Valid() bool { return m == OverwriteFail || m == OverwriteOverwrite }

// ParseOverwriteMode разбирает режим, отвергая значения вне словаря §6.4.
func ParseOverwriteMode(s string) (OverwriteMode, error) {
	if m := OverwriteMode(s); m.Valid() {
		return m, nil
	}
	return "", fmt.Errorf("domain: overwrite mode %q: want one of %v", s, AllOverwriteModes())
}

// AllOverwriteModes возвращает словарь §6.4 целиком, в порядке объявления.
func AllOverwriteModes() []OverwriteMode { return []OverwriteMode{OverwriteFail, OverwriteOverwrite} }
