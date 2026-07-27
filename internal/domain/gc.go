package domain

import "fmt"

// GCReason — причина постановки blob в очередь отложенного удаления, колонка
// `blob_gc.reason` (§6.10).
type GCReason string

// Значения GCReason. Перечень закрыт CHECK (reason IN (…)) в §6.10. Причины
// `overwrite` в перечне нет и быть не может: физический путь current content —
// функция от (owner_user_id, resource_id) и при overwrite не меняется, а
// публикация выполняется rename(staging → live), который сам отцепляет прежний
// inode (§5.4, §6.10).
const (
	// GCPurge — окончательное удаление ресурса или его версий.
	GCPurge GCReason = "purge"
	// GCVersionExpired — истёк retention сохранённой версии (§11.3).
	GCVersionExpired GCReason = "version_expired"
	// GCUploadExpired — staging-файл просроченной или неудавшейся загрузки.
	GCUploadExpired GCReason = "upload_expired"
	// GCFsck — осиротевший файл, найденный проверкой §21.3.
	GCFsck GCReason = "fsck"
	// GCOverwriteSource — blob источника MOVE с overwrite=true (§9.3): именно
	// он переезжает live/<src-id> → live/<tgt-id> под recovery marker.
	GCOverwriteSource GCReason = "overwrite_source"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.10.
func (r GCReason) Valid() bool {
	switch r {
	case GCPurge, GCVersionExpired, GCUploadExpired, GCFsck, GCOverwriteSource:
		return true
	}
	return false
}

// ParseGCReason разбирает причину, отвергая значения вне словаря §6.10.
func ParseGCReason(s string) (GCReason, error) {
	if v := GCReason(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: blob gc reason %q: want one of %v", s, AllGCReasons())
}

// AllGCReasons возвращает словарь §6.10 целиком, в порядке объявления.
func AllGCReasons() []GCReason {
	return []GCReason{GCPurge, GCVersionExpired, GCUploadExpired, GCFsck, GCOverwriteSource}
}
