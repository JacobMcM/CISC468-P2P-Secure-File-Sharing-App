package pages

import (
	"GoClient/discovery"
	"fmt"

	"GoClient/ui/msgs"
	"GoClient/ui/styles"

	tea "github.com/charmbracelet/bubbletea"
)

type HomeModel struct {
    peers []*discovery.Peer
	cursor int
}

func (m HomeModel) Init() tea.Cmd {
    return nil
}

func NewHome() HomeModel {
	return HomeModel{}
}

func (m HomeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
		switch key := msg.String(); key {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "down":
			if m.cursor < len(m.peers)-1 {
				m.cursor++
			}
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "enter":
			return m, func() tea.Msg {
				return msgs.NavigateMsg{Target: msgs.PageFiles, Payload: m.peers[m.cursor]}
			}

		}
    case msgs.PeerUpdateMsg:
        m.peers = []*discovery.Peer(msg)
    }
    return m, nil
}

func (m HomeModel) View() string {
    s := styles.Title.Render(fmt.Sprintf("Peers (%d)", len(m.peers))) + "\n\n"

    if len(m.peers) == 0 {
        s += styles.Dim.Render("  no peers discovered") + "\n"
    }

    for i, p := range m.peers {
		if i == m.cursor {
			s += fmt.Sprintf("  %s  %s\n",
				styles.Name.Render(fmt.Sprintf("[x] %s", p.Name)),
				styles.Addr.Render(fmt.Sprintf("%s:%d", p.IP, p.Port)),
			)	
		} else {
			s += fmt.Sprintf("  %s  %s\n",
				styles.Name.Render(fmt.Sprintf("[ ] %s", p.Name)),
				styles.Addr.Render(fmt.Sprintf("%s:%d", p.IP, p.Port)),
			)
		}
    }
    s += styles.Dim.Render("\nq: quit\n")
    s += styles.White.Render("\n--------------------------------------------------\n")
	
    return s
}