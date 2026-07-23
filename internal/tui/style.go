package tui

import (
	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// Тема «неоновый грид» — сдержанный киберпанк (docs/tz/04-tui-client.md §4).
// Палитра построена на базе Tokyo Night: тёмные поверхности + неоновые акценты,
// но без «кислотных» цветов. Цвета заданы в truecolor; lipgloss/colorprofile
// автоматически деградирует их до 256/16 цветов на старых терминалах, поэтому
// совместимость не страдает.
var (
	colBg0    = lipgloss.Color("#16161e") // самый глубокий фон: бары и футеры
	colBg2    = lipgloss.Color("#24283b") // приподнятая поверхность: вкладки, выделение
	colBorder = lipgloss.Color("#3b4261") // рамки карточек и разделительные линии
	colFg     = lipgloss.Color("#c0caf5") // основной текст
	colMuted  = lipgloss.Color("#565f89") // приглушённый текст, подсказки
	colCyan   = lipgloss.Color("#7dcfff") // главный акцент: активное, курсор, клавиши
	colBlue   = lipgloss.Color("#7aa2f7") // директории
	colPurple = lipgloss.Color("#bb9af7") // роль admin, градиент прогресса
	colPink   = lipgloss.Color("#f7768e") // ошибки и опасные действия
	colAmber  = lipgloss.Color("#e0af68") // новые файлы, события, предупреждения
	colMint   = lipgloss.Color("#9ece6a") // успех
	colTeal   = lipgloss.Color("#73daca") // .part-файлы, трафик, приглашение
)

// Общие стили командера и формы подключения.
var (
	styActiveTitle   = lipgloss.NewStyle().Bold(true).Foreground(colBg0).Background(colCyan).Padding(0, 1)
	styInactiveTitle = lipgloss.NewStyle().Foreground(colMuted).Background(colBg2).Padding(0, 1)

	styCursor = lipgloss.NewStyle().Bold(true).Foreground(colBg0).Background(colCyan)
	styDir    = lipgloss.NewStyle().Bold(true).Foreground(colBlue)
	styNew    = lipgloss.NewStyle().Bold(true).Foreground(colAmber)
	styPart   = lipgloss.NewStyle().Foreground(colTeal)
	stySelect = lipgloss.NewStyle().Bold(true).Foreground(colAmber).Background(colBg2)
	styDim    = lipgloss.NewStyle().Foreground(colMuted)
	styText   = lipgloss.NewStyle().Foreground(colFg)
	styAccent = lipgloss.NewStyle().Foreground(colCyan)

	styErr   = lipgloss.NewStyle().Bold(true).Foreground(colPink)
	styOK    = lipgloss.NewStyle().Foreground(colMint)
	styEvent = lipgloss.NewStyle().Foreground(colAmber)

	styFbar    = lipgloss.NewStyle().Foreground(colMuted).Background(colBg0)
	styFbarKey = lipgloss.NewStyle().Bold(true).Foreground(colCyan).Background(colBg0)
	styPrompt  = lipgloss.NewStyle().Bold(true).Foreground(colTeal)
	styPlaque  = lipgloss.NewStyle().Bold(true).Foreground(colBg0).Background(colPink)
)

// Стили админ-панели (docs/tz/05-admin.md §2): верхний бар, вкладки, карточки
// телеметрии, таблицы и центрированные модальные окна.
var (
	styAdminGlyph  = lipgloss.NewStyle().Foreground(colPurple)
	styAdminLogo   = lipgloss.NewStyle().Bold(true).Foreground(colCyan)
	styAdminServer = lipgloss.NewStyle().Bold(true).Foreground(colFg)

	styTabActive   = lipgloss.NewStyle().Bold(true).Foreground(colBg0).Background(colCyan).Padding(0, 1)
	styTabInactive = lipgloss.NewStyle().Foreground(colMuted).Padding(0, 1)
	styRule        = lipgloss.NewStyle().Foreground(colBorder)
	styRuleActive  = lipgloss.NewStyle().Foreground(colCyan)

	styCardBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).Padding(0, 1)
	styCardValue = lipgloss.NewStyle().Bold(true).Foreground(colFg)

	styTableHead    = lipgloss.NewStyle().Bold(true).Foreground(colMuted)
	styBadgeHot     = lipgloss.NewStyle().Foreground(colMint)
	styBadgeRestart = lipgloss.NewStyle().Foreground(colMuted)
	styRoleAdmin    = lipgloss.NewStyle().Bold(true).Foreground(colPurple)

	styModal            = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colCyan).Padding(1, 2)
	styModalDanger      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colPink).Padding(1, 2)
	styModalTitle       = lipgloss.NewStyle().Bold(true).Foreground(colCyan)
	styModalTitleDanger = lipgloss.NewStyle().Bold(true).Foreground(colPink)
)

func linkColor(l linkState) lipgloss.Style {
	switch l {
	case linkUp:
		return lipgloss.NewStyle().Foreground(colMint)
	case linkReconnect:
		return lipgloss.NewStyle().Foreground(colAmber)
	default:
		return lipgloss.NewStyle().Foreground(colPink)
	}
}

// newThemedInput возвращает поле ввода в палитре темы со СТАТИЧНЫМ курсором:
// мигание убрано осознанно (неоновый блок просто стоит на месте), поэтому
// нигде в программе не запускается textinput.Blink.
func newThemedInput() textinput.Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.PromptStyle = lipgloss.NewStyle().Foreground(colCyan)
	ti.TextStyle = styText
	ti.PlaceholderStyle = styDim
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(colBg0).Background(colCyan)
	_ = ti.Cursor.SetMode(cursor.CursorStatic)
	return ti
}
