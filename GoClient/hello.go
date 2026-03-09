package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// ------------------------
// Peer struct and map
// ------------------------
type Peer struct {
	Name     string
	IP       string
	Port     int
	TXT      []string
	LastSeen time.Time
}

var (
	peers   = make(map[string]*Peer)
	peersMu sync.Mutex // protect map
)

// ------------------------
// TCP server
// ------------------------
func startTCPServer(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("TCP server listening on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer func() {
		log.Println("Client disconnected:", conn.RemoteAddr())
		conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		log.Printf("Received from %s: %s\n", conn.RemoteAddr(), text)
		// Echo back
		conn.Write([]byte("Echo: " + text + "\n"))
	}

	if err := scanner.Err(); err != nil {
		log.Println("Connection error:", err)
	}
}

// ------------------------
// mDNS advertisement
// ------------------------
func advertiseService(name string, port int) *zeroconf.Server {
	server, err := zeroconf.Register(
		name,
		"_p2p._tcp",
		"local.",
		port,
		[]string{"Minimal P2P Service"},
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Advertising service %s on port %d\n", name, port)
	return server
}

// ------------------------
// mDNS discovery
// ------------------------
func discoverPeers(ctx context.Context, selfName string) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatal("Failed to initialize resolver:", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if entry.Instance == selfName {
				continue // ignore self
			}
			if len(entry.AddrIPv4) == 0 {
				continue
			}

			peersMu.Lock()
			peers[entry.Instance] = &Peer{
				Name:     entry.Instance,
				IP:       entry.AddrIPv4[0].String(),
				Port:     entry.Port,
				TXT:      entry.Text,
				LastSeen: time.Now(),
			}
			peersMu.Unlock()
		}
	}(entries)

	err = resolver.Browse(ctx, "_p2p._tcp", "local.", entries)
	if err != nil {
		log.Fatal("Failed to browse:", err)
	}
}

// ------------------------
// Peer cleanup
// ------------------------
func cleanupPeers(ttl time.Duration) {
	ticker := time.NewTicker(ttl / 3)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		peersMu.Lock()
		for k, p := range peers {
			if now.Sub(p.LastSeen) > ttl {
				log.Println("Removing offline peer:", k)
				delete(peers, k)
			}
		}
		peersMu.Unlock()
	}
}

// ------------------------
// Main
// ------------------------
func main() {
	const tcpPort = 5002
	const selfName = "Liam-PC"

	// Start TCP server
	go startTCPServer(tcpPort)

	// Advertise via mDNS
	mdnsServer := advertiseService(selfName, tcpPort)
	defer mdnsServer.Shutdown()

	// Discover peers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go discoverPeers(ctx, selfName)

	// Cleanup offline peers
	go cleanupPeers(100 * time.Second)

	// Print currently online peers periodically
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		peersMu.Lock()
		if len(peers) == 0 {
			fmt.Println("No peers online")
		} else {
			fmt.Println("Currently online peers:")
			for _, p := range peers {
				fmt.Printf("- %s @ %s:%d\n", p.Name, p.IP, p.Port)
			}
		}
		peersMu.Unlock()
	}
}