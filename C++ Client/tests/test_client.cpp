#include "network.h"
#include "mdns.h"
#include <iostream>

int main() {
    // Show available peers
    listPeers();

    std::string peerName;
    std::cout << "Enter peer name: ";
    std::getline(std::cin, peerName);

    if (discoveredPeers.find(peerName) == discoveredPeers.end()) {
        std::cerr << "Peer not found" << std::endl;
        return 1;
    }

    Peer& peer = discoveredPeers[peerName];
    int sock = connectToPeer(peer.ip, peer.port);
    if (sock < 0) return 1;

    std::string message;
    std::cout << "Enter message: ";
    std::getline(std::cin, message);

    sendMessage(sock, message);

    std::string reply = receiveMessage(sock);
    std::cout << "Reply: " << reply << std::endl;

    closeConnection(sock);
    return 0;
}