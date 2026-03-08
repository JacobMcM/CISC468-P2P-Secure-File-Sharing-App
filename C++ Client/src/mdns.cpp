#include "mdns.h"
#include <iostream>

// Called by Bonjour when registration succeeds or fails
void registerCallback(DNSServiceRef ref, DNSServiceFlags flags,
    DNSServiceErrorType err, const char* name,
    const char* type, const char* domain, void* context)
{
    // TODO
}

// Called by Bonjour when a peer is discovered on the network
void browseCallback(DNSServiceRef ref, DNSServiceFlags flags,
    uint32_t ifIndex, DNSServiceErrorType err,
    const char* name, const char* type, const char* domain,
    void* context)
{
    // TODO
}

DNSServiceRef registerPeer(const std::string& peerName, uint16_t port) {
    // TODO
    return nullptr;
}

DNSServiceRef browsePeers() {
    // TODO
    return nullptr;
}

void runMdnsLoop(DNSServiceRef registerRef, DNSServiceRef browseRef) {
    // TODO
}