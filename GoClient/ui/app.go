package ui

import (
	"GoClient/discovery"
	"GoClient/ui/msgs"
	"GoClient/ui/pages"
	"fmt"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// appModel is the top-level model that owns all pages and handles routing
type appModel struct {
	currentPage msgs.Page

	home   pages.HomeModel
	files  pages.FilesModel
}

func newApp() appModel {
	return appModel{
		currentPage: msgs.PageHome,
		home:        pages.NewHome(),
		files:       pages.NewFiles(),
	}
}

func StartShopApp() (tea.Model, error) {
	p := tea.NewProgram(newApp(), tea.WithAltScreen())
	fmt.Print("\033[H\033[2J")
	go WatchPeers(p)
    return p.Run()
}

func (m appModel) Init() tea.Cmd {
	return m.home.Init()
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle navigation at the top level
	if nav, ok := msg.(msgs.NavigateMsg); ok {
		m.currentPage = nav.Target

		// Pass payload to the destination page if present
		switch nav.Target {
		case msgs.PageFiles:
			if peer, ok := nav.Payload.(*discovery.Peer); ok {
				m.files = m.files.WithPeer(peer)
			}
		}

		// Fire the Init of the newly active page
		switch m.currentPage {
		case msgs.PageHome:
			return m, m.home.Init()
		case msgs.PageFiles:
			return m, m.files.Init()
		}
		return m, nil
	}

	// Delegate all other messages to the active page
	switch m.currentPage {
	case msgs.PageHome:
		updated, cmd := m.home.Update(msg)
		m.home = updated.(pages.HomeModel)
		return m, cmd
	case msgs.PageFiles:
		updated, cmd := m.files.Update(msg)
		m.files = updated.(pages.FilesModel)
		return m, cmd
	}

	return m, nil
}

func (m appModel) View() string {
	switch m.currentPage {
	case msgs.PageHome:
		return m.home.View()
	case msgs.PageFiles:
		return m.files.View()
	}
	return ""
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

            p.Send(msgs.PeerUpdateMsg(snapshot))
        } else {
            discovery.PeersMu.Unlock()
        }
    }
}