package metadata_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// Символы записаны \u-эскейпами намеренно: греческие «альфа» и «А», NFC- и
// NFD-форма «Å» выглядят в редакторе одинаково, и тест, который на них падает,
// невозможно прочитать. Комментарий рядом называет символ по имени Unicode.
const (
	alphaSmall    = "α"  // GREEK SMALL LETTER ALPHA
	alphaCapital  = "Α"  // GREEK CAPITAL LETTER ALPHA
	iotaCapital   = "Ι"  // GREEK CAPITAL LETTER IOTA
	iotaSubscript = "ͅ"  // COMBINING GREEK YPOGEGRAMMENI
	alphaYpoSmall = "ᾳ"  // GREEK SMALL ALPHA WITH YPOGEGRAMMENI
	alphaYpoCap   = "ᾼ"  // GREEK CAPITAL ALPHA WITH PROSGEGRAMMENI
	kelvin        = "K"  // KELVIN SIGN
	angstrom      = "Å"  // ANGSTROM SIGN
	aRingNFC      = "Å"  // LATIN CAPITAL LETTER A WITH RING ABOVE
	aRingNFD      = "Å" // A + COMBINING RING ABOVE — та же буква
	aRingSmall    = "å"  // LATIN SMALL LETTER A WITH RING ABOVE
	sharpSCapital = "ẞ"  // LATIN CAPITAL LETTER SHARP S
	sharpS        = "ß"  // LATIN SMALL LETTER SHARP S
	ligatureFF    = "ﬀ"  // LATIN SMALL LIGATURE FF
	dotlessI      = "ı"  // LATIN SMALL LETTER DOTLESS I
	dottedI       = "İ"  // LATIN CAPITAL LETTER I WITH DOT ABOVE
	// TIBETAN VOWEL SIGN II исключён из композиции: NFD его раскладывает, NFC
	// обратно не собирает, поэтому нормализованная форма ДЛИННЕЕ исходной —
	// 3 байта против 6.
	tibetanVowelII = "ཱི"
)

// nfcOf нужен тесту длины: он обязан знать обе формы имени, чтобы утверждать,
// какая из двух проверок сработала.
func nfcOf(s string) string { return norm.NFC.String(s) }

// foldCorpus — имена, на которых свёртывание §5.3 ломается, если написать его
// хоть немного иначе. Держится отдельно: его прогоняет тест на идемпотентность.
var foldCorpus = []string{
	"", "a.txt", "A.TXT", "Привет", "ПРИВЕТ", "CON.txt", "файл с пробелами.bin",
	alphaSmall + iotaCapital,     // свёртывание заглавной йоты даёт строчную
	alphaYpoSmall,                // та же пара, уже собранная NFC
	alphaYpoCap,                  // её заглавная форма
	alphaCapital + iotaSubscript, // и она же в разложенном виде
	kelvin, angstrom, aRingNFC, aRingNFD,
	sharpSCapital, "Stra" + sharpS + "e",
	ligatureFF, "ff", dottedI, dotlessI,
}

// TestFoldNameIdempotent — §24.1 п. 4: name_fold устойчиво к повторному
// применению. Свойство не декоративное: сервер пересчитывает колонку при каждой
// записи `name` (§6.3), и если бы второй проход давал другое значение, строка,
// переписанная в то же самое имя, перестала бы находиться по resources_fold —
// то есть детект регистровых коллизий молча отключился бы для части каталога.
func TestFoldNameIdempotent(t *testing.T) {
	for _, in := range foldCorpus {
		once := metadata.FoldName(in)
		twice := metadata.FoldName(once)
		if once != twice {
			t.Errorf("FoldName(%s) = %s, повторно = %s: не идемпотентно",
				dumpRunes(in), dumpRunes(once), dumpRunes(twice))
		}
	}
}

// TestFoldNameCollisions — какие имена §5.3 объявляет одним именем, а какие
// разными. Таблица нормативна: «обязаны совпасть» — это конфликт, отклоняемый
// при storage.case_conflict_detect = true; «обязаны различаться» — два законных
// соседних файла, и ложный конфликт сделал бы невозможной законную операцию.
func TestFoldNameCollisions(t *testing.T) {
	same := [][2]string{
		{"a.txt", "A.TXT"},                            // регистр ASCII
		{"Привет", "ПРИВЕТ"},                          // регистр вне ASCII
		{aRingNFC, aRingNFD},                          // NFC против NFD
		{angstrom, aRingSmall},                        // знак Ангстрема против å
		{kelvin, "k"},                                 // знак Кельвина против k
		{alphaYpoSmall, alphaYpoCap},                  // строчная против заглавной
		{alphaCapital + iotaSubscript, alphaYpoSmall}, // та же пара разложенной
	}
	for _, p := range same {
		if got, want := metadata.FoldName(p[0]), metadata.FoldName(p[1]); got != want {
			t.Errorf("FoldName(%s) = %s, FoldName(%s) = %s: обязаны совпасть",
				dumpRunes(p[0]), dumpRunes(got), dumpRunes(p[1]), dumpRunes(want))
		}
	}

	// Полное (full) свёртывание схлопнуло бы первые две пары; §6.3 требует
	// ПРОСТОГО, и эти строки — единственное, что отличает одно от другого.
	differ := [][2]string{
		{ligatureFF, "ff"},                 // лигатура против двух букв
		{"Stra" + sharpS + "e", "Strasse"}, // ß против ss
		{dotlessI, "i"},                    // ı без точки против i
		{"a.txt", "b.txt"},                 // просто разные имена
	}
	for _, p := range differ {
		if got, want := metadata.FoldName(p[0]), metadata.FoldName(p[1]); got == want {
			t.Errorf("FoldName(%s) == FoldName(%s) == %s: обязаны различаться",
				dumpRunes(p[0]), dumpRunes(p[1]), dumpRunes(got))
		}
	}
}

// TestValidateName — правила §5.3 п. 1–6, каждое отдельной строкой.
func TestValidateName(t *testing.T) {
	valid := []string{
		"a.txt", "Привет.bin", "файл с пробелами.txt", ".hidden", "..hidden",
		"a?b", "a*b", `a"b`, "a<b>c", "a|b", // §5.3: POSIX-имена, сервер их разрешает
		"COM0", "LPT0", "CONS", "PRNTR", // похожи на зарезервированные, но не они
		strings.Repeat("x", domain.MaxNameLen),
	}
	for _, name := range valid {
		if err := metadata.ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []struct{ name, why string }{
		{"", "п. 1: пустое"},
		{"\xff\xfe", "п. 1: невалидный UTF-8"},
		{".", "п. 2"},
		{"..", "п. 2"},
		{"a/b", "п. 3: разделитель"},
		{`a\b`, "п. 3: разделитель"},
		{"a:b", "п. 3: разделитель"},
		{"a\x00b", "п. 3: NUL"},
		{"a\tb", "п. 3: управляющий U+0009"},
		{"a\x7Fb", "п. 3: управляющий U+007F"},
		{"a.", "п. 4: хвостовая точка"},
		{"a ", "п. 4: хвостовой пробел"},
		{"CON", "п. 5"},
		{"con", "п. 5: без учёта регистра"},
		{"CON.txt", "п. 5: с расширением"},
		{"com9.tar.gz", "п. 5: с двойным расширением"},
		{"NUL", "п. 5"},
		{"lpt1", "п. 5"},
		{strings.Repeat("x", domain.MaxNameLen+1), "п. 6: длина"},
	}
	for _, tc := range invalid {
		err := metadata.ValidateName(tc.name)
		if err == nil {
			t.Errorf("ValidateName(%q) = nil, want error (%s)", tc.name, tc.why)
			continue
		}
		if !errors.Is(err, metadata.ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, ожидалась обёртка ErrInvalidName (%s)", tc.name, err, tc.why)
		}
	}
}

// TestValidateNameLength — предел §5.3 п. 6 проверяется у ОБЕИХ форм имени, и
// ни одна проверка не следует из другой.
//
// Исходная форма ограничена потому, что именно она идёт по проводу и читается
// декодером через r.str(MaxNameLen): имя длиннее предела в сыром виде дало бы
// ресурс, чей листинг ни один клиент не разберёт. Форма NFC — потому, что она
// бывает ДЛИННЕЕ исходной у символов, исключённых из композиции.
func TestValidateNameLength(t *testing.T) {
	// Ровно предел в обеих формах — принимается.
	if err := metadata.ValidateName(strings.Repeat("x", domain.MaxNameLen)); err != nil {
		t.Errorf("имя ровно в предел отвергнуто: %v", err)
	}

	// Влезает после NFC (240 байт), но не влезает как есть (360). Хранится и
	// передаётся исходная форма, поэтому отказ.
	nfd := strings.Repeat(aRingNFD, 120)
	if len(nfd) <= domain.MaxNameLen || len(nfcOf(nfd)) > domain.MaxNameLen {
		t.Fatalf("подготовка теста: raw = %d, NFC = %d", len(nfd), len(nfcOf(nfd)))
	}
	if err := metadata.ValidateName(nfd); !errors.Is(err, metadata.ErrInvalidName) {
		t.Errorf("ValidateName(%d байт как есть, %d после NFC) = %v, want ErrInvalidName: "+
			"такое имя не разберёт ни один клиент", len(nfd), len(nfcOf(nfd)), err)
	}

	// Обратный случай: влезает как есть (255 байт), но не влезает после NFC
	// (520). Проверка одной только исходной длины пропустила бы его.
	tibetan := strings.Repeat(tibetanVowelII, 85)
	if len(tibetan) > domain.MaxNameLen || len(nfcOf(tibetan)) <= domain.MaxNameLen {
		t.Fatalf("подготовка теста: raw = %d, NFC = %d", len(tibetan), len(nfcOf(tibetan)))
	}
	if err := metadata.ValidateName(tibetan); !errors.Is(err, metadata.ErrInvalidName) {
		t.Errorf("ValidateName(%d байт как есть, %d после NFC) = %v, want ErrInvalidName (§5.3 п. 6)",
			len(tibetan), len(nfcOf(tibetan)), err)
	}
}

// dumpRunes печатает строку кодовыми точками: в сообщении об ошибке про
// свёртывание «альфа» и «А» неразличимы, а U+03B1 и U+0391 — нет.
func dumpRunes(s string) string {
	if s == "" {
		return "<empty>"
	}
	var b strings.Builder
	for _, r := range s {
		if r > 0x20 && r < 0x7F {
			fmt.Fprintf(&b, "%c", r)
			continue
		}
		fmt.Fprintf(&b, "[U+%04X]", r)
	}
	return b.String()
}
