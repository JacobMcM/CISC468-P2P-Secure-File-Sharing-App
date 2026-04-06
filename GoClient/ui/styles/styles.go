package styles

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	pink   = lipgloss.Color("#FF69B4")
	purple = lipgloss.Color("#9B59B6")
	gray   = lipgloss.Color("#626262")
	white  = lipgloss.Color("#FAFAFA")

	// Subtitle / description
	Subtitle = lipgloss.NewStyle().
			Foreground(purple).
			MarginBottom(1)

	// Selected item in a list
	Selected = lipgloss.NewStyle().
			Bold(true).
			Foreground(white).
			Background(purple).
			PaddingLeft(1).
			PaddingRight(1)

	// Unselected item
	Normal = lipgloss.NewStyle().
		Foreground(white).
		PaddingLeft(1).
		PaddingRight(1)

	// Dimmed hint text
	Hint = lipgloss.NewStyle().
		Foreground(gray)

	// Detail box
	Box = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(purple).
		Padding(1, 2).
		MarginTop(1)

	Title    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
    Name     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
    Addr     = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
    Dim      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
    White    = lipgloss.NewStyle().Foreground(lipgloss.Color("#eaeaea"))
    Stale    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")) // yellow for stale peers
)