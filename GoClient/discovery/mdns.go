package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

type Peer struct {
	Name     string
	IP       string
	Port     int
	TXT      []string
	FileList []string
	LastSeen time.Time
}

var (
	Peers   = make(map[string]*Peer)
	PeersMu sync.Mutex
)

func RegisterMdnsServer(name string, port int) *zeroconf.Server {
	server, err := zeroconf.Register(
		name,
		"_p2p._tcp",
		"local.",
		port,
		[]string{"Liam's p2p file sharing client"},
		nil,
	)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Advertising service %s on port %d\n", name, port)
	return server
}

func StartPeerDiscovery(ctx context.Context, selfName string) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatal("Failed to initialize resolver:", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if entry.Instance == selfName {
				continue
			}
			if len(entry.AddrIPv4) == 0 {
				continue
			}

			PeersMu.Lock()
			if _, exists := Peers[entry.Instance]; !exists {
				// New peer discovered
				peer := &Peer{
					Name:     entry.Instance,
					IP:       entry.AddrIPv4[0].String(),
					Port:     entry.Port,
					TXT:      entry.Text,
					FileList: []string{"file1", "file2", "file3"},
					LastSeen: time.Now(),
				}
				Peers[entry.Instance] = peer
				PeersMu.Unlock()
			} else {
				// Update last seen
				Peers[entry.Instance].LastSeen = time.Now()
				PeersMu.Unlock()
			}
		}
	}(entries)

	err = resolver.Browse(ctx, "_p2p._tcp", "local.", entries)
	if err != nil {
		log.Fatal("Failed to browse:", err)
	}
}

func StartPeerCleaning(ttl time.Duration) {
	ticker := time.NewTicker(ttl / 3)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		PeersMu.Lock()
		for k, p := range Peers {
			if now.Sub(p.LastSeen) > ttl {
				log.Println("Removing offline peer:", k)
				delete(Peers, k)
			}
		}
		PeersMu.Unlock()
	}
}

func StartPeerLogging() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		PeersMu.Lock()
		if len(Peers) == 0 {
			fmt.Println("No peers online")
		} else {
			fmt.Println("Currently online peers:")
			for _, p := range Peers {
				fmt.Printf("- %s @ %s:%d, Last Seen: %s\n", p.Name, p.IP, p.Port, p.LastSeen.Format("15:04:05"))
			}
		}
		PeersMu.Unlock()
	}
}

func StartHeartbeat(ctx context.Context) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            case <-time.After(10 * time.Second):
                PeersMu.Lock()
                for name, peer := range Peers {
                    if !pingPeer(peer) {
                        delete(Peers, name)
                    } else {
                        peer.LastSeen = time.Now()
                    }
                }
                PeersMu.Unlock()
            }
        }
    }()
}

func pingPeer(peer *Peer) bool {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port), 2*time.Second)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}