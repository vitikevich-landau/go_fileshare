package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// clipTo обрезает строку до w экранных колонок, не ломая ANSI-стили
// (fit из view.go считает руны и годится только для НЕстилизованных строк).
func clipTo(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "")
}

// fitCols подгоняет s ровно под w экранных КОЛОНОК (не рун): усекает с
// многоточием либо дополняет пробелами по display-width. В отличие от fit()
// это корректно для строк с широкими (CJK/emoji) символами — иначе строка под
// курсором (с фоновой заливкой) на широких символах вышла бы на колонку короче
// и потеряла бы «…». Строка должна быть без ANSI-стилей (усечение — по рунам).
func fitCols(s string, w int) string {
	if w < 0 {
		w = 0
	}
	sw := lipgloss.Width(s)
	if sw > w {
		// Усечение может дать w-1 колонку, если бюджет упёрся в широкий символ
		// (частичную ячейку вписать нельзя) — добиваем пробелом ниже.
		s = ansi.Truncate(s, w, "…")
		sw = lipgloss.Width(s)
	}
	if sw < w {
		s += strings.Repeat(" ", w-sw)
	}
	return s
}

// overlayCenter кладёт многострочный бокс fg поверх кадра bg по центру области
// width×height — так модальные окна админ-панели рисуются НАД контентом, а не
// приклеиваются строчкой к низу экрана. Каждая затронутая строка нормализуется
// ровно до width колонок, поэтому композиция устойчива к широким символам на
// линии разреза (иначе ansi.Truncate/TruncateLeft дали бы строку в width∓1
// колонку и сдвинули бы модалку/фон на колонку). Стили вокруг выреза сохраняются.
func overlayCenter(bg, fg string, width, height int) string {
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")

	fgW := 0
	for _, l := range fgLines {
		if w := lipgloss.Width(l); w > fgW {
			fgW = w
		}
	}
	x := (width - fgW) / 2
	if x < 0 {
		x = 0
	}
	y := (height - len(fgLines)) / 2
	if y < 0 {
		y = 0
	}

	for i, fl := range fgLines {
		row := y + i
		if row >= len(bgLines) {
			break
		}
		base := bgLines[row]
		if w := lipgloss.Width(base); w < width {
			base += strings.Repeat(" ", width-w)
		}
		// Левый сегмent фона [0..x). Если x попал внутрь широкого символа,
		// ansi.Truncate отбросит его целиком и вернёт x-1 колонку — добиваем
		// пробелом, чтобы модалка не съехала влево на этой строке.
		left := ansi.Truncate(base, x, "")
		if lw := lipgloss.Width(left); lw < x {
			left += strings.Repeat(" ", x-lw)
		}
		// Правый сегмент фона с колонки x+fgW. Модальную строку добиваем до fgW.
		right := ansi.TruncateLeft(base, x+fgW, "")
		pad := ""
		if lw := lipgloss.Width(fl); lw < fgW {
			pad = strings.Repeat(" ", fgW-lw)
		}
		// Финальная нормализация строки ровно до width: срезаем лишнюю колонку
		// (без многоточия — режется фон, а не смысловой текст), если правый
		// разрез пришёлся на широкий символ (TruncateLeft его сохраняет),
		// и добиваем до полной ширины кадра.
		merged := left + fl + pad + right
		if mw := lipgloss.Width(merged); mw > width {
			merged = clipTo(merged, width)
		} else if mw < width {
			merged += strings.Repeat(" ", width-mw)
		}
		bgLines[row] = merged
	}
	return strings.Join(bgLines, "\n")
}
