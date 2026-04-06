#include "mdns.h"
#include <iostream>
#include <cstring>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <netdb.h>
#endif

// Global map of discovered peers
std::map<std::string, Peer> discoveredPeers;

// Called by Bonjour when registration succeeds or fails
void registerCallback(DNSServiceRef ref, DNSServiceFlags flags,
    DNSServiceErrorType err, const char* name,
    const char* type, const char* domain, void* context)
{
    if (err == kDNSServiceErr_NoError) {
        std::cout << "Registered: " << name << " on network" << std::endl;
    } else {
        std::cerr << "Registration failed: " << err << std::endl;
    }
}

// Step 3: Called when we get the IP address from resolving
void resolveAddrCallback(DNSServiceRef ref, DNSServiceFlags flags,
    uint32_t ifIndex, DNSServiceErrorType err,
    const char* hostname, const struct sockaddr* address,
    uint32_t ttl, void* context)
{
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Address resolve failed: " << err << std::endl;
        DNSServiceRefDeallocate(ref);
        return;
    }

    // Extract the peer name we stored in context
    std::string peerName = *(std::string*)context;

    // Convert the address to a readable IP string
    if (address->sa_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)address;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));

        // Update the peer's IP in our map
        if (discoveredPeers.count(peerName)) {
            discoveredPeers[peerName].ip = ip;
            std::cout << "Peer resolved: " << peerName
                      << " at " << ip
                      << ":" << discoveredPeers[peerName].port << std::endl;
        }
    }

    delete (std::string*)context;
    DNSServiceRefDeallocate(ref);
}

// Step 2: Called when Bonjour resolves a service name to hostname and port
void resolveCallback(DNSServiceRef ref, DNSServiceFlags flags,
    uint32_t ifIndex, DNSServiceErrorType err,
    const char* fullname, const char* hostname,
    uint16_t port, uint16_t txtLen,
    const unsigned char* txtRecord, void* context)
{
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Resolve failed: " << err << std::endl;
        DNSServiceRefDeallocate(ref);
        return;
    }

    // Extract the peer name we stored in context
    std::string peerName = *(std::string*)context;

    // Store the port (convert from network byte order)
    discoveredPeers[peerName].port = ntohs(port);

    // Now get the actual IP from the hostname
    DNSServiceRef addrRef;
    DNSServiceGetAddrInfo(&addrRef, 0, ifIndex,
        kDNSServiceProtocol_IPv4, hostname,
        resolveAddrCallback, context); // pass the name along

    // Process the result immediately
    DNSServiceProcessResult(addrRef);

    DNSServiceRefDeallocate(ref);
}

// Step 1: Called by Bonjour when a peer is discovered on the network
void browseCallback(DNSServiceRef ref, DNSServiceFlags flags,
    uint32_t ifIndex, DNSServiceErrorType err,
    const char* name, const char* type, const char* domain,
    void* context)
{
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Browse error: " << err << std::endl;
        return;
    }

    if (flags & kDNSServiceFlagsAdd) {
        std::cout << "Peer joined: " << name << std::endl;

        // Add to our map with empty IP for now
        Peer peer;
        peer.name = name;
        peer.ip = "";
        peer.port = 0;
        discoveredPeers[name] = peer;

        // Resolve to get their IP and port
        // Store the name on the heap so callbacks can access it
        std::string* peerName = new std::string(name);

        DNSServiceRef resolveRef;
        DNSServiceResolve(&resolveRef, 0, ifIndex,
            name, type, domain,
            resolveCallback, peerName);

        // Process the result immediately
        DNSServiceProcessResult(resolveRef);

    } else {
        std::cout << "Peer left: " << name << std::endl;
        discoveredPeers.erase(name);
    }
}

DNSServiceRef registerPeer(const std::string& peerName, uint16_t port) {
    DNSServiceRef ref;
    DNSServiceErrorType err = DNSServiceRegister(
        &ref, 0, 0,
        peerName.c_str(),
        "_p2p._tcp.",
        "local.",
        nullptr,
        htons(port),
        0, nullptr,
        registerCallback, nullptr);

    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Failed to register service: " << err << std::endl;
        return nullptr;
    }
    return ref;
}

DNSServiceRef browsePeers() {
    DNSServiceRef ref;
    DNSServiceErrorType err = DNSServiceBrowse(
        &ref, 0, 0,
        "_p2p._tcp.",
        "local.",
        browseCallback, nullptr);

    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Failed to browse: " << err << std::endl;
        return nullptr;
    }
    return ref;
}

void listPeers() {
    std::cout << "\n--- Discovered Peers ---" << std::endl;
    for (auto& [name, peer] : discoveredPeers) {
        std::cout << name << " at " << peer.ip << ":" << peer.port << std::endl;
    }
    std::cout << "------------------------\n" << std::endl;
}

void runMdnsLoop(DNSServiceRef registerRef, DNSServiceRef browseRef) {
    int registerFd = DNSServiceRefSockFD(registerRef);
    int browseFd = DNSServiceRefSockFD(browseRef);

    std::cout << "Listening for peers..." << std::endl;

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(registerFd, &fds);
        FD_SET(browseFd, &fds);
        int maxFd = std::max(registerFd, browseFd) + 1;

        if (select(maxFd, &fds, nullptr, nullptr, nullptr) > 0) {
            if (FD_ISSET(registerFd, &fds))
                DNSServiceProcessResult(registerRef);
            if (FD_ISSET(browseFd, &fds))
                DNSServiceProcessResult(browseRef);
        }
    }
}