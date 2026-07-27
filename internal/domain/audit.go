package domain

import "fmt"

// AuditResult — исход события аудита, колонка `audit_events.result` (§6.9).
type AuditResult string

// Значения AuditResult. Перечень закрыт
// CHECK (result IN ('ok','denied','error')).
const (
	AuditOK     AuditResult = "ok"
	AuditDenied AuditResult = "denied"
	AuditError  AuditResult = "error"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.9.
func (r AuditResult) Valid() bool {
	switch r {
	case AuditOK, AuditDenied, AuditError:
		return true
	}
	return false
}

// ParseAuditResult разбирает исход, отвергая значения вне словаря §6.9.
func ParseAuditResult(s string) (AuditResult, error) {
	if v := AuditResult(s); v.Valid() {
		return v, nil
	}
	return "", fmt.Errorf("domain: audit result %q: want one of %v", s, AllAuditResults())
}

// AllAuditResults возвращает словарь §6.9 целиком, в порядке объявления.
func AllAuditResults() []AuditResult { return []AuditResult{AuditOK, AuditDenied, AuditError} }
