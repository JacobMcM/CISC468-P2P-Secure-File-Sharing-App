#ifndef MDNS_H
#define MDNS_H

#ifdef _WIN32 // Platform-specific header for network byte order conversion (htons)
    #include <winsock2.h> // Windows
#else
    #include <arpa/inet.h> // macOS/Linux
#endif

#include <dns_sd.h> // Bonjour API for mDNS peer discovery
#include <string>

// Register this peer on the network so others can discover us, returns a handle to the active registration
DNSServiceRef registerPeer(const std::string& peerName, uint16_t port);

// Start scanning the network for other peers, returns a handle to the active browsing session
DNSServiceRef browsePeers();

// Event loop that processes mDNS discovery events, runs forever, checking both handles for activity
void runMdnsLoop(DNSServiceRef registerRef, DNSServiceRef browseRef);

#endif