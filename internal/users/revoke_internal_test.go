package users

import "testing"

// TestRevocationTableMatchesSpec — таблица §7.4, переписанная из документа
// НЕЗАВИСИМО от объявления в revoke.go.
//
// Смысл именно в независимости. Проверять таблицу её же значениями бессмысленно,
// а наблюдаемое поведение (тесты через spy) показывает, что операция делает, но
// не показывает, что перечень операций полон: забытая строка выглядит как
// «операция ничего не отзывает», то есть как штатное поведение. Поэтому здесь
// сверяются ОБА свойства — совпадение с документом и полнота перечня.
//
//	операция       сессии                токены       shares
//	user disable   закрываются           отзываются   suspended
//	user enable    —                     —            suspended -> active
//	user passwd    закрываются           отзываются   —
//	user role      пересчёт UserContext  отзываются   —
//	user quota     пересчёт UserContext  —            —
//	user delete    закрываются           отзываются   revoked
//	user purge     —                     —            —
func TestRevocationTableMatchesSpec(t *testing.T) {
	spec := map[operation]revocation{
		operation("user disable"): {sessions: sessionsClosed, tokens: true, shares: ShareSuspended},
		operation("user enable"):  {sessions: sessionsUntouched, tokens: false, shares: ShareActive},
		operation("user passwd"):  {sessions: sessionsClosed, tokens: true, shares: ""},
		operation("user role"):    {sessions: sessionsRecomputed, tokens: true, shares: ""},
		operation("user quota"):   {sessions: sessionsRecomputed, tokens: false, shares: ""},
		operation("user delete"):  {sessions: sessionsClosed, tokens: true, shares: ShareRevoked},
		operation("user purge"):   {sessions: sessionsUntouched, tokens: false, shares: ""},
	}

	if len(revocationTable) != len(spec) {
		t.Errorf("в таблице §7.4 %d строк, в документе %d", len(revocationTable), len(spec))
	}
	for op, want := range spec {
		got, ok := revocationTable[op]
		if !ok {
			t.Errorf("операция %q не имеет строки в revocationTable", op)
			continue
		}
		if got != want {
			t.Errorf("строка %q = %+v, документ требует %+v", op, got, want)
		}
	}
	for op := range revocationTable {
		if _, ok := spec[op]; !ok {
			t.Errorf("в revocationTable есть операция %q, которой нет в таблице §7.4", op)
		}
	}
}

// TestAllOperationsAreCovered — перечень allOperations обязан совпадать с
// таблицей: он и есть то, по чему тесты обходят операции, и операция, выпавшая из
// перечня, перестала бы проверяться, оставаясь рабочей.
func TestAllOperationsAreCovered(t *testing.T) {
	seen := map[operation]bool{}
	for _, op := range allOperations() {
		if seen[op] {
			t.Errorf("операция %q перечислена дважды", op)
		}
		seen[op] = true
		if _, ok := revocationTable[op]; !ok {
			t.Errorf("операция %q не имеет строки в revocationTable", op)
		}
	}
	for op := range revocationTable {
		if !seen[op] {
			t.Errorf("операция %q отсутствует в allOperations", op)
		}
	}
}

// TestApplyRevocationPanicsOnUnknownOperation — пропущенная строка таблицы
// означает неисполненную §7.4, то есть неотозванные привилегии. Молчание здесь
// хуже паники, и тест закрепляет именно это решение.
func TestApplyRevocationPanicsOnUnknownOperation(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("applyRevocation не запаниковал на операции вне таблицы")
		}
	}()
	s := &Service{sessions: noSessions{}, tokens: noTokens{}, shares: noShares{}}
	s.applyRevocation(t.Context(), operation("user rename"), 1)
}
