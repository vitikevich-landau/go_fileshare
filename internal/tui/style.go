package tui

import "github.com/charmbracelet/lipgloss"

// A 16-color-friendly palette in the spirit of Midnight Commander
// (docs/tz/04-tui-client.md §4).
var (
	colBlue   = lipgloss.Color("4")
	colCyan   = lipgloss.Color("6")
	colWhite  = lipgloss.Color("15")
	colGray   = lipgloss.Color("7")
	colYellow = lipgloss.Color("11")
	colRed    = lipgloss.Color("9")
	colGreen  = lipgloss.Color("10")
	colBlack  = lipgloss.Color("0")

	styActiveTitle   = lipgloss.NewStyle().Bold(true).Foreground(colBlack).Background(colCyan).Padding(0, 1)
	styInactiveTitle = lipgloss.NewStyle().Foreground(colWhite).Background(colBlue).Padding(0, 1)

	styCursor = lipgloss.NewStyle().Foreground(colBlack).Background(colCyan)
	styDir    = lipgloss.NewStyle().Bold(true).Foreground(colWhite)
	styNew    = lipgloss.NewStyle().Bold(true).Foreground(colYellow)
	styPart   = lipgloss.NewStyle().Foreground(colCyan)
	stySelect = lipgloss.NewStyle().Foreground(colYellow).Background(colBlue)
	styDim    = lipgloss.NewStyle().Foreground(colGray)

	styErr   = lipgloss.NewStyle().Bold(true).Foreground(colRed)
	styOK    = lipgloss.NewStyle().Foreground(colGreen)
	styEvent = lipgloss.NewStyle().Foreground(colYellow)

	styFbar   = lipgloss.NewStyle().Foreground(colBlack).Background(colCyan)
	styPrompt = lipgloss.NewStyle().Foreground(colGreen)
)

func linkColor(l linkState) lipgloss.Style {
	switch l {
	case linkUp:
		return lipgloss.NewStyle().Foreground(colGreen)
	case linkReconnect:
		return lipgloss.NewStyle().Foreground(colYellow)
	default:
		return lipgloss.NewStyle().Foreground(colRed)
	}
}
