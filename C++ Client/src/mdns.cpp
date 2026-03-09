#include "mdns.h"
#include <iostream>

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

// Called by Bonjour when a peer is discovered on the network
void browseCallback(DNSServiceRef ref, DNSServiceFlags flags,
    uint32_t ifIndex, DNSServiceErrorType err,
    const char* name, const char* type, const char* domain,
    void* context)
{
    if (err == kDNSServiceErr_NoError) {
        if (flags & kDNSServiceFlagsAdd) {
            std::cout << "Peer joined: " << name << std::endl;
        } else {
            std::cout << "Peer left: " << name << std::endl;
        }
    } else {
        std::cerr << "Browse error: " << err << std::endl;
    }
}

DNSServiceRef registerPeer(const std::string& peerName, uint16_t port) {
    DNSServiceRef ref;
    DNSServiceErrorType err = DNSServiceRegister(
        &ref,              // handle we get back
        0,                 // no special flags
        0,                 // any network interface
        peerName.c_str(),  // your name on the network
        "_p2p._tcp.",      // service type — must match Python and Go
        "local.",          // local network only
        nullptr,           // let system pick the host
        htons(port),       // your port in network byte order
        0,                 // no TXT record data yet
        nullptr,           // no TXT record data yet
        registerCallback,  // function Bonjour calls when done
        nullptr);          // no extra context

    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Failed to register service: " << err << std::endl;
        return nullptr;
    }
    return ref;
}

DNSServiceRef browsePeers() {
    DNSServiceRef ref;
    DNSServiceErrorType err = DNSServiceBrowse(
        &ref,              // handle we get back
        0,                 // no special flags
        0,                 // any network interface
        "_p2p._tcp.",      // service type: must match Python and Go
        "local.",          // local network only
        browseCallback,    // function Bonjour calls when peer found
        nullptr);          // no extra context

    if (err != kDNSServiceErr_NoError) {
        std::cerr << "Failed to browse: " << err << std::endl;
        return nullptr;
    }
    return ref;
}

void runMdnsLoop(DNSServiceRef registerRef, DNSServiceRef browseRef) {
    // Get the socket file descriptors from Bonjour
    int registerFd = DNSServiceRefSockFD(registerRef);
    int browseFd = DNSServiceRefSockFD(browseRef);

    std::cout << "Listening for peers..." << std::endl;

    while (true) {
        // Set up which sockets to watch
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(registerFd, &fds);
        FD_SET(browseFd, &fds);
        int maxFd = std::max(registerFd, browseFd) + 1;

        // Wait until something happens on either socket
        if (select(maxFd, &fds, nullptr, nullptr, nullptr) > 0) {
            // If registration has an update, process it
            if (FD_ISSET(registerFd, &fds))
                DNSServiceProcessResult(registerRef);
            // If browsing found something, process it
            if (FD_ISSET(browseFd, &fds))
                DNSServiceProcessResult(browseRef);
        }
    }
}