package metadata

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// TestFoldOrbitRepresentativeIsCanonical — два свойства, на которых держится
// колонка name_fold, проверяются обходом ВСЕГО диапазона Unicode, а не корпусом
// примеров.
//
// Постоянство на орбите: все кодовые точки, объявленные Unicode эквивалентными
// при простом свёртывании, обязаны давать одно и то же значение. Нарушь его — и
// два регистровых варианта одного имени получат разные name_fold, то есть
// коллизия просто не найдётся, молча и только для части алфавитов.
//
// Идемпотентность (§24.1 п. 4): повторное применение ничего не меняет.
//
// Ровно эти два свойства и ломались у очевидных альтернатив. Наименьший по коду
// член орбиты неидемпотентен на греческой йоте; порунный cases.Fold из x/text
// для пары чероки U+13A0 и U+AB70 меняет символы местами, то есть не постоянен
// на орбите и не идемпотентен сразу.
func TestFoldOrbitRepresentativeIsCanonical(t *testing.T) {
	var orbitRunes, badConstant, badIdempotent int
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		got := foldOrbitRepresentative(r)
		if again := foldOrbitRepresentative(got); again != got {
			badIdempotent++
			if badIdempotent <= 5 {
				t.Errorf("не идемпотентно: U+%04X -> U+%04X -> U+%04X", r, got, again)
			}
		}
		inOrbit := false
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			inOrbit = true
			if other := foldOrbitRepresentative(f); other != got {
				badConstant++
				if badConstant <= 5 {
					t.Errorf("не постоянно на орбите: U+%04X -> U+%04X, но эквивалентный ему U+%04X -> U+%04X",
						r, got, f, other)
				}
			}
		}
		if inOrbit {
			orbitRunes++
		}
	}

	// Обход обязан что-то найти: если орбит вдруг ноль, тест зелен по недосмотру.
	if orbitRunes < 2000 {
		t.Fatalf("рун в нетривиальных орбитах = %d, ожидались тысячи: обход сломан", orbitRunes)
	}
	if badConstant != 0 || badIdempotent != 0 {
		t.Errorf("нарушений постоянства = %d, неидемпотентных = %d", badConstant, badIdempotent)
	}
}

// TestFoldOrbitRepresentativeStaysInOrbit — представитель обязан быть ЧЛЕНОМ
// своей орбиты, а не произвольным символом: name_fold должен оставаться именем,
// эквивалентным исходному, иначе он перестаёт быть его свёрткой.
func TestFoldOrbitRepresentativeStaysInOrbit(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		got := foldOrbitRepresentative(r)
		if got == r {
			continue
		}
		found := false
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f == got {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("U+%04X -> U+%04X, которого нет в его орбите", r, got)
		}
	}
}
