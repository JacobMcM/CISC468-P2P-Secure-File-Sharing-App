package discovery

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
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

type PeerPubKeyRecord struct {
	Name      string `json:"name"`
    PublicKey string `json:"public_key"`
}

type PeerPubKeyDB struct {
    PeerPubKeys []PeerPubKeyRecord `json:"peer_pub_keys"`
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

	// // REMOVE LATER
	// PeersMu.Lock()
	// peer := &Peer{
	// 	Name:     "Fake1",
	// 	IP:       "123.456.78.9",
	// 	Port:     1000,
	// 	TXT:      []string{"somefile.txt"},
	// 	FileList: []string{"somefile.txt", "file2.txt", "file3.txt"},
	// 	LastSeen: time.Now(),
	// }
	// Peers[peer.Name] = peer;
	// PeersMu.Unlock()

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
			log.Printf("Discovered: %s at %s:%d\n", entry.Instance, entry.AddrIPv4, entry.Port)

			// if entry.Instance == selfName {
			// 	continue
			// }
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

func LoadPeerKeys(path string) (map[string]*rsa.PublicKey, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var peerPubKeyDB PeerPubKeyDB
    if err := json.Unmarshal(data, &peerPubKeyDB); err != nil {
        return nil, err
    }

    keys := make(map[string]*rsa.PublicKey)
    for _, peer := range peerPubKeyDB.PeerPubKeys {
        block, _ := pem.Decode([]byte(peer.PublicKey))
        pub, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
            return nil, fmt.Errorf("peer %s: invalid public key: %w", peer.Name, err)
        }
        keys[peer.Name] = pub.(*rsa.PublicKey)
    }

    return keys, nil
}

func AddPeerRecord(path, name, b64Key string) error {
    der, err := base64.StdEncoding.DecodeString(b64Key)
    if err != nil {
        return err
    }
    if _, err := x509.ParsePKIXPublicKey(der); err != nil {
        return fmt.Errorf("invalid public key: %w", err)
    }

    pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

    var peerPubKeyDB PeerPubKeyDB
    data, err := os.ReadFile(path)
    if err != nil && !os.IsNotExist(err) {
        return err
    }
    if len(data) > 0 {
        json.Unmarshal(data, &peerPubKeyDB)
    }

    peerPubKeyDB.PeerPubKeys = append(peerPubKeyDB.PeerPubKeys, PeerPubKeyRecord{Name: name, PublicKey: pemStr})

    out, _ := json.MarshalIndent(peerPubKeyDB, "", "  ")
    return os.WriteFile(path, out, 0644)
}