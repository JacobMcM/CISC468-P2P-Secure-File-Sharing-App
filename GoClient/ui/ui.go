package ui

import (
	"GoClient/discovery"
	"fmt"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Messages ---
type peerUpdateMsg []*discovery.Peer

// --- Model ---
type model struct {
    peers []*discovery.Peer
	cursor int
}

func (m model) Init() tea.Cmd {
    return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		}
    case peerUpdateMsg:
        m.peers = []*discovery.Peer(msg)
    }
    return m, nil
}

var (
    titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
    nameStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
    addrStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
    dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
    whiteStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#eaeaea"))
    staleStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")) // yellow for stale peers
)

func (m model) View() string {
    s := titleStyle.Render(fmt.Sprintf("Peers (%d)", len(m.peers))) + "\n\n"

    if len(m.peers) == 0 {
        s += dimStyle.Render("  no peers discovered") + "\n"
    }

    for i, p := range m.peers {
		if i == m.cursor {
			s += fmt.Sprintf("  %s  %s\n",
				nameStyle.Render(fmt.Sprintf("[x] %s", p.Name)),
				addrStyle.Render(fmt.Sprintf("%s:%d", p.IP, p.Port)),
			)	
		} else {
			s += fmt.Sprintf("  %s  %s\n",
				nameStyle.Render(fmt.Sprintf("[ ] %s", p.Name)),
				addrStyle.Render(fmt.Sprintf("%s:%d", p.IP, p.Port)),
			)
		}
    }
    s += dimStyle.Render("\nq: quit")
    return s
}

func WatchPeers(p *tea.Program) {
    var lastCount int

	peer1 := &discovery.Peer{
		Name:     "Fake1",
		IP:       "123.456.78.9",
		Port:     1000,
		TXT:      []string{"somefile.txt"},
		FileList: []string{"somefile.txt", "file2.txt", "file3.txt"},
		LastSeen: time.Now(),
	}
	peer2 := &discovery.Peer{
		Name:     "Fake1",
		IP:       "123.456.78.9",
		Port:     1000,
		TXT:      []string{"somefile.txt"},
		FileList: []string{"somefile.txt", "file2.txt", "file3.txt"},
		LastSeen: time.Now(),
	}
	peer3 := &discovery.Peer{
		Name:     "Fake1",
		IP:       "123.456.78.9",
		Port:     1000,
		TXT:      []string{"somefile.txt"},
		FileList: []string{"somefile.txt", "file2.txt", "file3.txt"},
		LastSeen: time.Now(),
	}

    for {
        time.Sleep(500 * time.Millisecond)

        discovery.PeersMu.Lock()
        if len(discovery.Peers) != lastCount {
            lastCount = len(discovery.Peers)

            snapshot := make([]*discovery.Peer, 0, len(discovery.Peers))
            for _, peer := range discovery.Peers {
                snapshot = append(snapshot, peer)
            }
			snapshot = append(snapshot, peer1)
			snapshot = append(snapshot, peer2)
			snapshot = append(snapshot, peer3)
            discovery.PeersMu.Unlock()

            sort.Slice(snapshot, func(i, j int) bool {
                return snapshot[i].Name < snapshot[j].Name
            })

            p.Send(peerUpdateMsg(snapshot))
        } else {
            discovery.PeersMu.Unlock()
        }
    }
}

func Start() (tea.Model, error) {
    m := model{}
    p := tea.NewProgram(m)
    go WatchPeers(p)
	//Cear terminal
	fmt.Print("\033[H\033[2J")
    return p.Run()
}