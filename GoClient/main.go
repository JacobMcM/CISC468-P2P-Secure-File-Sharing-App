package main

import (
	"context"
	"time"

	"GoClient/crypto"
	"GoClient/discovery"
	"GoClient/network"
	"GoClient/ui"
)



func main() {

	crypto.Main()
	select {}
	const tcpPort = 5011
	const selfName = "Liam-PC"

	// Start TCP server
	go network.StartTCPServer(tcpPort)

	// Advertise via mDNS
	mdnsServer := discovery.RegisterMdnsServer(selfName, tcpPort)
	defer mdnsServer.Shutdown()

	// Discover peers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go discovery.StartPeerDiscovery(ctx, selfName)
	go discovery.StartPeerCleaning(11 * time.Second)
	// go discovery.StartPeerLogging()
	discovery.StartHeartbeat(ctx)
	ui.StartShopApp()
	
	select {}
	
}