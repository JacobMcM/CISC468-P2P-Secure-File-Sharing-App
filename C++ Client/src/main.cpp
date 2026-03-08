#include "mdns.h"
#include <iostream>

int main() {
    std::cout << "Starting P2P client..." << std::endl;

    auto registerRef = registerPeer("Cameron Mac", 5001);
    if (!registerRef) {
        std::cerr << "Failed to register peer" << std::endl;
        return 1;
    }

    auto browseRef = browsePeers();
    if (!browseRef) {
        std::cerr << "Failed to start browsing" << std::endl;
        return 1;
    }

    runMdnsLoop(registerRef, browseRef);

    DNSServiceRefDeallocate(registerRef);
    DNSServiceRefDeallocate(browseRef);
    return 0;
}