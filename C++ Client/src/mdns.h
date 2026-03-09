#ifndef MDNS_H
#define MDNS_H

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#include <dns_sd.h>
#include <string>
#include <map>

// Stores info about a discovered peer
struct Peer {
    std::string name;
    std::string ip;
    uint16_t port;
};

// All discovered peers, keyed by name
extern std::map<std::string, Peer> discoveredPeers;

DNSServiceRef registerPeer(const std::string& peerName, uint16_t port);
DNSServiceRef browsePeers();
void runMdnsLoop(DNSServiceRef registerRef, DNSServiceRef browseRef);

// Print all currently discovered peers
void listPeers();

#endif