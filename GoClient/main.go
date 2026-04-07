package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"GoClient/crypto"
	"GoClient/discovery"
	file "GoClient/file_manager"
	"GoClient/transport"
)



func main() {
	const tcpPort = 5011
	const selfName = "Liam-PC"

    if !file.FileExists("keys/private.pem") || !file.FileExists("keys/public.pem") {
        GenerateAndSaveRSAKeys()
    }

    if !file.FileExists("files/file_list.json") {
        myPrivKey, _ := crypto.LoadPrivateKey("keys/private.pem")
        file.InitFileList("files", myPrivKey, selfName)
    }

	// Start TCP server
	go transport.StartTCPServer(tcpPort)

	// Advertise self via mDNS
	mdnsServer := discovery.RegisterMdnsServer(selfName, tcpPort)
	defer mdnsServer.Shutdown()

	// Discover peers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go discovery.StartPeerDiscovery(ctx, selfName)
	go StartREPL(selfName)
	
	select {}
}

func StartREPL(selfName string) {
    scanner := bufio.NewScanner(os.Stdin)
    fmt.Println("Enter a peer name to connect, or 'peers' to list:")

    for {
        fmt.Print("> ")
        if !scanner.Scan() {
            break
        }
        input := strings.TrimSpace(scanner.Text())

        switch input {
        case "":
            continue
        case "peers":
            discovery.PeersMu.Lock()
            if len(discovery.Peers) == 0 {
                fmt.Println("No peers online")
            } else {
                for name, p := range discovery.Peers {
                    fmt.Printf("  - %s @ %s:%d\n", name, p.IP, p.Port)
                }
            }
            discovery.PeersMu.Unlock()

        default:
            // treat input as peer name
            discovery.PeersMu.Lock()
            peer, ok := discovery.Peers[input]
            discovery.PeersMu.Unlock()

            if !ok {
                fmt.Printf("Unknown peer: %s\n", input)
                continue
            }

            fmt.Printf("Connecting to %s...\n", peer.Name)
            fmt.Print("Enter shared password: ")
            if !scanner.Scan() {
                break
            }
            password := strings.TrimSpace(scanner.Text())

            secureSession, err := transport.ConnectToPeer(peer, selfName, password)
            if err != nil {
                fmt.Printf("Failed to connect to %s: %v\n", peer.Name, err)
                continue
            }

            fmt.Printf("Connected to %s\n", peer.Name)
            transport.RunSecureClientSession(secureSession)
        }
    }
}

func GenerateAndSaveRSAKeys() error {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

	os.MkdirAll("keys", 0755)

    privFile, _ := os.Create("keys/private.pem")
    pem.Encode(privFile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })
    privFile.Close()

    pubFile, _ := os.Create("keys/public.pem")
    pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    pem.Encode(pubFile, &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pubBytes,
    })
    pubFile.Close()

    return nil
}