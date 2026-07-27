package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestIDCanonicalForm — идентификатор ходит по кругу «сгенерировали → текст →
// разобрали» без потерь и всегда в 32 символах нижнего регистра hex (§2.1).
func TestIDCanonicalForm(t *testing.T) {
	id, err := domain.NewResourceID()
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	s := id.String()
	if len(s) != 32 {
		t.Fatalf("len(%q) = %d, want 32", s, len(s))
	}
	if s != strings.ToLower(s) {
		t.Fatalf("%q is not lowercase", s)
	}
	back, err := domain.ParseResourceID(s)
	if err != nil {
		t.Fatalf("ParseResourceID(%q): %v", s, err)
	}
	if back != id {
		t.Fatalf("round-trip: got %v, want %v", back, id)
	}
	if id.IsZero() {
		t.Fatal("generated id is zero")
	}
}

// TestIDRejectsNonCanonical — верхний регистр отвергается наравне с мусором:
// иначе один идентификатор имел бы два текстовых представления, то есть два
// разных значения TEXT PRIMARY KEY (§6.3) и два разных пути (§5.1).
func TestIDRejectsNonCanonical(t *testing.T) {
	cases := map[string]string{
		"пусто":            "",
		"короткий":         "0123456789abcdef",
		"длинный":          strings.Repeat("a", 33),
		"верхний регистр":  "0123456789ABCDEF0123456789ABCDEF",
		"не hex":           "0123456789abcdef0123456789abcdeg",
		"с разделителями":  "01234567-89ab-cdef-0123-456789ab",
		"нецифровой мусор": strings.Repeat("z", 32),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := domain.ParseResourceID(s); err == nil {
				t.Fatalf("ParseResourceID(%q) = nil error, want rejection", s)
			}
			if _, err := domain.ParseUploadID(s); err == nil {
				t.Fatalf("ParseUploadID(%q) = nil error, want rejection", s)
			}
			if _, err := domain.ParseTrashID(s); err == nil {
				t.Fatalf("ParseTrashID(%q) = nil error, want rejection", s)
			}
		})
	}
}

// TestIDsAreDistinct — генератор не повторяется на коротком горизонте.
func TestIDsAreDistinct(t *testing.T) {
	seen := make(map[domain.ResourceID]bool, 512)
	for i := 0; i < 512; i++ {
		id, err := domain.NewResourceID()
		if err != nil {
			t.Fatalf("NewResourceID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %s at iteration %d", id, i)
		}
		seen[id] = true
	}
}

// TestClosedVocabularies — каждый закрытый словарь §6 разбирается по своим
// значениям и отвергает чужие. Список All*() — тот самый перечень, который
// миграция 0001 повторяет в CHECK; их совпадение проверяет тест схемы в
// internal/db.
func TestClosedVocabularies(t *testing.T) {
	t.Run("role", func(t *testing.T) {
		for _, v := range domain.AllRoles() {
			if got, err := domain.ParseRole(string(v)); err != nil || got != v {
				t.Fatalf("ParseRole(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseRole("root"); err == nil {
			t.Fatal("ParseRole(\"root\") accepted")
		}
	})
	t.Run("user state", func(t *testing.T) {
		for _, v := range domain.AllUserStates() {
			if got, err := domain.ParseUserState(string(v)); err != nil || got != v {
				t.Fatalf("ParseUserState(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseUserState("enabled"); err == nil {
			t.Fatal("ParseUserState(\"enabled\") accepted")
		}
		if !domain.UserActive.CanAuthenticate() {
			t.Fatal("active user cannot authenticate")
		}
		for _, v := range []domain.UserState{domain.UserDisabled, domain.UserPendingDelete} {
			if v.CanAuthenticate() {
				t.Fatalf("%q must not authenticate", v)
			}
		}
	})
	t.Run("kdf algo", func(t *testing.T) {
		for _, v := range domain.AllKDFAlgos() {
			if got, err := domain.ParseKDFAlgo(string(v)); err != nil || got != v {
				t.Fatalf("ParseKDFAlgo(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseKDFAlgo("scrypt"); err == nil {
			t.Fatal("ParseKDFAlgo(\"scrypt\") accepted")
		}
	})
	t.Run("namespace", func(t *testing.T) {
		for _, v := range domain.AllNamespaces() {
			if got, err := domain.ParseNamespace(string(v)); err != nil || got != v {
				t.Fatalf("ParseNamespace(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseNamespace("shared"); err == nil {
			t.Fatal("ParseNamespace(\"shared\") accepted")
		}
	})
	t.Run("kind", func(t *testing.T) {
		for _, v := range domain.AllKinds() {
			if got, err := domain.ParseKind(string(v)); err != nil || got != v {
				t.Fatalf("ParseKind(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseKind("symlink"); err == nil {
			t.Fatal("ParseKind(\"symlink\") accepted")
		}
		// На этом байтовом порядке держится SortKindNameAsc (§6.3).
		if !(domain.KindDir < domain.KindFile) {
			t.Fatal("'dir' must sort before 'file'")
		}
	})
	t.Run("upload state", func(t *testing.T) {
		for _, v := range domain.AllUploadStates() {
			if got, err := domain.ParseUploadState(string(v)); err != nil || got != v {
				t.Fatalf("ParseUploadState(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseUploadState("done"); err == nil {
			t.Fatal("ParseUploadState(\"done\") accepted")
		}
	})
	t.Run("overwrite mode", func(t *testing.T) {
		for _, v := range domain.AllOverwriteModes() {
			if got, err := domain.ParseOverwriteMode(string(v)); err != nil || got != v {
				t.Fatalf("ParseOverwriteMode(%q) = %q, %v", v, got, err)
			}
		}
		// Режима rename у загрузок нет — он существует только у restore (§10.2).
		if _, err := domain.ParseOverwriteMode("rename"); err == nil {
			t.Fatal("ParseOverwriteMode(\"rename\") accepted")
		}
	})
	t.Run("change op", func(t *testing.T) {
		for _, v := range domain.AllChangeOps() {
			if got, err := domain.ParseChangeOp(string(v)); err != nil || got != v {
				t.Fatalf("ParseChangeOp(%q) = %q, %v", v, got, err)
			}
		}
		// Второго имени для того же факта в журнале не существует (§6.7).
		for _, bad := range []string{"delete", "restore"} {
			if _, err := domain.ParseChangeOp(bad); err == nil {
				t.Fatalf("ParseChangeOp(%q) accepted", bad)
			}
		}
	})
	t.Run("share state", func(t *testing.T) {
		for _, v := range domain.AllShareStates() {
			if got, err := domain.ParseShareState(string(v)); err != nil || got != v {
				t.Fatalf("ParseShareState(%q) = %q, %v", v, got, err)
			}
		}
		// Истечение срока — производное от expires_at_ms, а не четвёртое
		// состояние (§6.8).
		if _, err := domain.ParseShareState("expired"); err == nil {
			t.Fatal("ParseShareState(\"expired\") accepted")
		}
	})
	t.Run("audit result", func(t *testing.T) {
		for _, v := range domain.AllAuditResults() {
			if got, err := domain.ParseAuditResult(string(v)); err != nil || got != v {
				t.Fatalf("ParseAuditResult(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseAuditResult("failed"); err == nil {
			t.Fatal("ParseAuditResult(\"failed\") accepted")
		}
	})
	t.Run("gc reason", func(t *testing.T) {
		for _, v := range domain.AllGCReasons() {
			if got, err := domain.ParseGCReason(string(v)); err != nil || got != v {
				t.Fatalf("ParseGCReason(%q) = %q, %v", v, got, err)
			}
		}
		// Причины overwrite в перечне нет и быть не может (§6.10).
		if _, err := domain.ParseGCReason("overwrite"); err == nil {
			t.Fatal("ParseGCReason(\"overwrite\") accepted")
		}
	})
	t.Run("secret name", func(t *testing.T) {
		for _, v := range domain.AllSecretNames() {
			if got, err := domain.ParseSecretName(string(v)); err != nil || got != v {
				t.Fatalf("ParseSecretName(%q) = %q, %v", v, got, err)
			}
		}
		if _, err := domain.ParseSecretName("tls_key"); err == nil {
			t.Fatal("ParseSecretName(\"tls_key\") accepted")
		}
	})
}

// TestUploadTransitions проверяет ИСЧЕРПЫВАЮЩИЙ перечень §6.4 полной матрицей:
// каждая пара состояний либо в ожидаемом множестве, либо запрещена. Тест
// повторяет перечень независимо от uploadTransitions, поэтому правка таблицы без
// правки спецификации его роняет (§24.1 п. 6).
func TestUploadTransitions(t *testing.T) {
	terminal := []domain.UploadState{
		domain.UploadCompleted, domain.UploadCancelled,
		domain.UploadFailed, domain.UploadExpired,
	}
	abort := []domain.UploadState{domain.UploadCancelled, domain.UploadExpired, domain.UploadFailed}

	want := map[domain.UploadState]map[domain.UploadState]bool{
		domain.UploadCreated:    {domain.UploadReceiving: true},
		domain.UploadReceiving:  {domain.UploadVerifying: true},
		domain.UploadVerifying:  {domain.UploadCommitting: true, domain.UploadReceiving: true},
		domain.UploadCommitting: {domain.UploadCompleted: true, domain.UploadReceiving: true},
	}
	// Из любого нетерминального состояния доступны cancelled/expired/failed.
	for from := range want {
		for _, to := range abort {
			want[from][to] = true
		}
	}

	for _, from := range domain.AllUploadStates() {
		for _, to := range domain.AllUploadStates() {
			got := domain.CanTransition(from, to)
			if got != want[from][to] {
				t.Errorf("CanTransition(%q, %q) = %v, want %v", from, to, got, want[from][to])
			}
		}
	}

	for _, s := range terminal {
		if !s.IsTerminal() {
			t.Errorf("%q must be terminal", s)
		}
		if got := domain.AllowedTransitions(s); len(got) != 0 {
			t.Errorf("AllowedTransitions(%q) = %v, want none", s, got)
		}
	}
	for _, s := range domain.ActiveUploadStates() {
		if s.IsTerminal() {
			t.Errorf("%q must not be terminal", s)
		}
	}
	if len(domain.ActiveUploadStates())+len(terminal) != len(domain.AllUploadStates()) {
		t.Fatal("active + terminal must cover every upload state")
	}
}

// TestAllowedTransitionsIsACopy — вызывающий не может испортить общую таблицу.
func TestAllowedTransitionsIsACopy(t *testing.T) {
	got := domain.AllowedTransitions(domain.UploadCreated)
	if len(got) == 0 {
		t.Fatal("created must have transitions")
	}
	got[0] = domain.UploadCompleted
	if domain.CanTransition(domain.UploadCreated, domain.UploadCompleted) {
		t.Fatal("AllowedTransitions returned a live slice: created -> completed became allowed")
	}
}

// TestChecksumAlgoWire — соответствие §6.1 между текстовыми колонками и
// проводным ChecksumAlgo uint8. Пакет domain не импортирует proto, поэтому
// совпадение констант проверяется здесь.
func TestChecksumAlgoWire(t *testing.T) {
	cases := []struct {
		algo domain.ChecksumAlgo
		wire proto.Algo
		sig  int
	}{
		{domain.ChecksumPending, proto.AlgoPending, 0},
		{domain.ChecksumCRC32, proto.AlgoCRC32, 4},
		{domain.ChecksumSHA256, proto.AlgoSHA256, 32},
	}
	for _, c := range cases {
		code, ok := c.algo.WireCode()
		if !ok {
			t.Fatalf("WireCode(%q) not ok", c.algo)
		}
		if code != uint8(c.wire) {
			t.Fatalf("WireCode(%q) = %d, want %d (proto)", c.algo, code, uint8(c.wire))
		}
		back, err := domain.ChecksumAlgoFromWire(code)
		if err != nil || back != c.algo {
			t.Fatalf("ChecksumAlgoFromWire(%d) = %q, %v; want %q", code, back, err, c.algo)
		}
		if got := c.algo.SignificantBytes(); got != c.sig {
			t.Fatalf("SignificantBytes(%q) = %d, want %d", c.algo, got, c.sig)
		}
	}
	if _, err := domain.ChecksumAlgoFromWire(3); err == nil {
		t.Fatal("ChecksumAlgoFromWire(3) accepted: any other value is malformed input")
	}
	// В БД ChecksumPending — это NULL, а не строка: в CHECK его нет.
	for _, a := range domain.AllChecksumAlgos() {
		if a == domain.ChecksumPending {
			t.Fatal("AllChecksumAlgos must not contain the pending value")
		}
	}
	if _, err := domain.ParseChecksumAlgo("md5"); err == nil {
		t.Fatal("ParseChecksumAlgo(\"md5\") accepted")
	}
}

// TestUnixMillis — кодировка §6.1 переживает круг и не тащит за собой локальную
// зону.
func TestUnixMillis(t *testing.T) {
	src := time.Date(2026, 7, 27, 10, 0, 0, 123_000_000, time.UTC)
	ms := domain.ToMillis(src)
	if int64(ms) != src.UnixMilli() {
		t.Fatalf("ToMillis = %d, want %d", ms, src.UnixMilli())
	}
	if got := ms.Time(); !got.Equal(src) || got.Location() != time.UTC {
		t.Fatalf("Time() = %v (%v), want %v (UTC)", got, got.Location(), src)
	}
	if got := ms.Add(90 * time.Second); !got.Time().Equal(src.Add(90 * time.Second)) {
		t.Fatalf("Add(90s) = %v, want %v", got.Time(), src.Add(90*time.Second))
	}
	if got, want := ms.String(), "2026-07-27T10:00:00.123Z"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if now := domain.NowMillis(); now <= 0 {
		t.Fatalf("NowMillis() = %d", now)
	}
}

// TestSystemAccountConstants — значения §2.1/§6.2, на которые опирается seed
// миграции 0001.
func TestSystemAccountConstants(t *testing.T) {
	if domain.SystemUserID != 0 {
		t.Fatalf("SystemUserID = %d, want 0", domain.SystemUserID)
	}
	if domain.SystemLogin != "system" {
		t.Fatalf("SystemLogin = %q, want \"system\"", domain.SystemLogin)
	}
	if domain.SecretValueLen != 32 {
		t.Fatalf("SecretValueLen = %d, want 32", domain.SecretValueLen)
	}
	if got, want := string(domain.LegacySalt("alice")), "fileshare-v2:alice"; got != want {
		t.Fatalf("LegacySalt = %q, want %q", got, want)
	}
}

// TestBaselineID — §6.7, §14.6: идентификатор baseline непрозрачен и имеет ту
// же каноническую форму, что прочие идентификаторы §2.1, потому что уходит
// клиенту в CURSOR_EXPIRED.Details, где допустимы только короткие ASCII-строки.
func TestBaselineID(t *testing.T) {
	id, err := domain.NewBaselineID()
	if err != nil {
		t.Fatalf("NewBaselineID: %v", err)
	}
	if !id.Valid() {
		t.Fatalf("NewBaselineID produced %q, which is not canonical", id)
	}
	if len(id) != 32 {
		t.Fatalf("len(%q) = %d, want 32", id, len(id))
	}
	for _, bad := range []domain.BaselineID{"", "not-hex", "0123456789ABCDEF0123456789ABCDEF"} {
		if bad.Valid() {
			t.Errorf("%q accepted as a baseline id", bad)
		}
	}
	other, err := domain.NewBaselineID()
	if err != nil {
		t.Fatalf("NewBaselineID: %v", err)
	}
	if other == id {
		t.Fatal("two baseline ids collided")
	}
}
