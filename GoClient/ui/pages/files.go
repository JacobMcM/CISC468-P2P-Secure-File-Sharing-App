package pages

import (
	"GoClient/discovery"
	"GoClient/ui/msgs"
	"GoClient/ui/styles"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type FilesModel struct{
	peer *discovery.Peer
	cursor int
}

func NewFiles() FilesModel {
	return FilesModel{}
}

func (m FilesModel) Init() tea.Cmd {
	return nil
}

func (m FilesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg {
				return msgs.NavigateMsg{Target: msgs.PageHome}
			}
		case "down":
			if m.cursor < len(m.peer.FileList)-1 {
				m.cursor++
			}
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		}
	}
	return m, nil
}

func (m FilesModel) View() string {
    if m.peer.Name == "" {
        return styles.Hint.Render("No peer selected.")
    }

	s := styles.Title.Render(m.peer.Name + " - " + m.peer.IP) + "\n\n"

    for i, fileName := range m.peer.FileList {
		if i == m.cursor {
			s += fmt.Sprintf("  %s\n",
				styles.Name.Render(fmt.Sprintf("[x] %s", fileName)),
			)	
		} else {
			s += fmt.Sprintf("  %s\n",
				styles.Name.Render(fmt.Sprintf("[ ] %s", fileName)),
			)
		}
    }
    s += styles.Dim.Render("\nesc: back\n")
    s += styles.White.Render("\n--------------------------------------------------\n")
    return s
}

// WithDrink returns a new DetailModel populated with the given drink
func (m FilesModel) WithPeer(peer *discovery.Peer) FilesModel {
	m.peer = peer
	return m
}