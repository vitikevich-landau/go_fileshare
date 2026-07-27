package metadata

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// ErrInvalidName — нарушение правил имени §5.3 п. 1–6. На границе server этот
// класс ошибок отображается в код INVALID_NAME (§5.3, §22); отличать его от
// ErrNameExists обязан вызывающий, потому что коды разные.
var ErrInvalidName = errors.New("metadata: invalid name")

// FoldName возвращает производную величину `name_fold` — casefold(NFC(name))
// (§5.3, колонка `resources.name_fold` §6.3).
//
// Значение служит ровно двум целям: детекту регистровых и нормализационных
// коллизий при `storage.case_conflict_detect = true` и именованию keyed locks
// (§23.1) — последнее НЕЗАВИСИМО от значения ключа конфигурации, чтобы
// конкурентные операции над `A.txt` и `a.txt` сериализовались в любом режиме.
// Клиенту значение не отдаётся никогда, само `name` хранится байт-в-байт таким,
// каким его прислал клиент (§5.3).
//
// Свёртывание — ПРОСТОЕ (simple case folding), как требует §6.3, а не полное.
// Разница видна пользователю: полное свёртывание схлопывает `ﬀ` в `ff` и `ß` в
// `ss`, то есть отклонило бы создание `ff.txt` рядом с `ﬀ.txt` как конфликт,
// которого нет ни на NTFS, ни на APFS. Ложный конфликт здесь дороже пропущенного:
// он делает невозможной операцию, законную на всех целевых ФС.
//
// Идемпотентность (FoldName(FoldName(x)) == FoldName(x)) — требование §24.1 п. 4.
// Она не обеспечивается ни конструкцией, ни повторной нормализацией на выходе, а
// проверяется тестом на корпусе: свёртывание может выдать последовательность,
// которую NFC собрала бы иначе, и единственный способ утверждать устойчивость —
// прогнать её на тех символах, где она ломается (греческая йота U+0345, знаки
// Кельвина и Ангстрема, NFD-разложения).
func FoldName(name string) string {
	return strings.Map(simpleFoldRune, norm.NFC.String(name))
}

// simpleFoldRune возвращает представителя орбиты простого свёртывания.
//
// unicode.SimpleFold обходит орбиту по кругу, но не назначает в ней канонического
// члена, поэтому его выбирает эта функция. Берётся СТРОЧНЫЙ член орбиты, а не
// наименьший по коду: у ASCII наименьший — это 'A' (0x41 < 0x61), и представителем
// стало бы `A.TXT`, то есть колонка name_fold заполнилась бы верхним регистром.
// Само по себе это ещё корректный канонизатор, но на составных символах он
// разъезжается: 'α' свернулось бы в 'Α', NFC собрала бы 'Α' + U+0345 обратно в
// U+1FBC, и повторное применение дало бы уже другое значение — идемпотентность
// §24.1 п. 4 нарушена. Строчный представитель этой ловушки не имеет.
func simpleFoldRune(r rune) rune {
	best, haveLower := r, unicode.IsLower(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		switch {
		case unicode.IsLower(f) && (!haveLower || f < best):
			best, haveLower = f, true
		case !haveLower && f < best:
			best = f
		}
	}
	return best
}

// winReserved — зарезервированные имена Windows (§5.3 п. 5). Хранятся в верхнем
// регистре: сравнение выполняется без учёта регистра.
var winReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidateName проверяет имя одного компонента пути по правилам §5.3 п. 1–6.
// Все возвращаемые ошибки оборачивают ErrInvalidName.
//
// Проверяется ИМЯ, а не путь: правила §5.3 п. 7–9 (MaxPathLen, MaxTreeDepth,
// форма VirtualPath) относятся к разбору пути целиком и вводятся вместе с ним.
//
// Символы `*`, `?`, `"`, `<`, `>`, `|` разрешены сознательно (§5.3): daemon
// работает только на POSIX (§5.6), а переносом таких имён на Windows и macOS
// занимается клиент по правилам §15.13. Запрещать их на сервере значило бы
// сделать недоступной часть законных POSIX-имён.
//
// Имя корня namespace — пустая строка (§6.3), и правило 1 её отвергает. Это не
// противоречие: корни создаются не пользовательской операцией, а миграцией и
// созданием пользователя, и через ValidateName не проходят.
func ValidateName(name string) error {
	// §5.3 п. 1: непустая строка в валидном UTF-8.
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: name is not valid UTF-8", ErrInvalidName)
	}
	// §5.3 п. 2.
	if name == "." || name == ".." {
		return fmt.Errorf("%w: name %q is reserved", ErrInvalidName, name)
	}
	// §5.3 п. 3.
	for _, r := range name {
		switch {
		case r == '/' || r == '\\' || r == ':':
			return fmt.Errorf("%w: name %q contains a path separator %q", ErrInvalidName, name, r)
		case r <= 0x1F || r == 0x7F:
			return fmt.Errorf("%w: name %q contains control character U+%04X", ErrInvalidName, name, r)
		}
	}
	// §5.3 п. 4. Хвостовая точка и пробел невидимы в большинстве UI и молча
	// отбрасываются Windows, поэтому два разных имени стали бы одним.
	if last := name[len(name)-1]; last == '.' || last == ' ' {
		return fmt.Errorf("%w: name %q ends with %q", ErrInvalidName, name, last)
	}
	// §5.3 п. 5: сравнение без учёта регистра и с любым расширением, поэтому
	// смотрится часть до первой точки: запрещены и `con`, и `CON.txt`.
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if winReserved[strings.ToUpper(base)] {
		return fmt.Errorf("%w: name %q is a reserved Windows device name", ErrInvalidName, name)
	}
	// §5.3 п. 6 меряет предел ПОСЛЕ нормализации NFC, а в колонку уходит
	// исходная форма (§5.3, «сервер хранит имя байт-в-байт»). Поэтому проверок
	// две, и ни одна не следует из другой.
	//
	// Исходная форма ограничена потому, что именно она идёт по проводу: имя
	// уезжает клиенту как есть, а декодер читает его через r.str(MaxNameLen)
	// (`internal/proto/messages.go`). Имя длиннее предела в сыром виде дало бы
	// ресурс, чей листинг ни один клиент не разберёт, — строку в базе, которую
	// никто никогда не увидит. §5.3 п. 6 этого не запрещает буквально, но и
	// ссылается ровно на ту же константу proto.MaxNameLen.
	//
	// Форма NFC ограничена отдельно, потому что она бывает ДЛИННЕЕ исходной:
	// у символов, исключённых из композиции, NFD раскладывает, а NFC обратно не
	// собирает. Тибетский U+0F73 занимает 3 байта и 6 после NFC, так что 85
	// таких знаков — это ровно 255 сырых байт и 520 нормализованных. Проверка
	// одной только исходной длины пропустила бы такое имя.
	if len(name) > domain.MaxNameLen {
		return fmt.Errorf("%w: name is %d bytes as stored, limit is %d",
			ErrInvalidName, len(name), domain.MaxNameLen)
	}
	if n := len(norm.NFC.String(name)); n > domain.MaxNameLen {
		return fmt.Errorf("%w: name is %d bytes after NFC, limit is %d",
			ErrInvalidName, n, domain.MaxNameLen)
	}
	return nil
}
