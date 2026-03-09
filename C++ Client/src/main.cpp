#include "mdns.h"
#include "network.h"
#include <iostream>
#include <thread>

int main() {
    std::cout << "Starting P2P client..." << std::endl;

    // Step 1: Start TCP server
    int server = startServer(5001);
    if (server < 0) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    // Step 2: Register on mDNS
    auto registerRef = registerPeer("Cameron Mac", 5001);
    if (!registerRef) {
        std::cerr << "Failed to register peer" << std::endl;
        return 1;
    }

    // Step 3: Start scanning for peers
    auto browseRef = browsePeers();
    if (!browseRef) {
        std::cerr << "Failed to start browsing" << std::endl;
        return 1;
    }

    // Step 4: Run mDNS in a separate thread
    std::thread mdnsThread(runMdnsLoop, registerRef, browseRef);
    mdnsThread.detach();

    // Step 5: Accept incoming connections in a separate thread
    std::thread serverThread([&server]() {
    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(server, (sockaddr*)&clientAddr, &clientLen);

        if (clientSocket < 0) continue;

        std::cout << "\nPeer connected!" << std::endl;

        // Try reading raw bytes
        char buffer[4096];
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead > 0) {
            std::cout << "Received (" << bytesRead << " bytes): " << std::string(buffer, bytesRead) << std::endl;
        } else {
            std::cout << "No data received" << std::endl;
        }

        closeConnection(clientSocket);
        std::cout << "> ";
        std::flush(std::cout);
    }
});
    serverThread.detach();

    
    // Step 6: Command loop
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  list  - Show discovered peers" << std::endl;
    std::cout << "  send  - Send a message to a peer" << std::endl;
    std::cout << "  quit  - Exit the program" << std::endl;

    std::string input;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);

        if (input == "list") {
            listPeers();

        } else if (input == "send") {
            listPeers();
            std::string peerName;
            std::cout << "Enter peer name: ";
            std::getline(std::cin, peerName);

            if (discoveredPeers.find(peerName) == discoveredPeers.end()) {
                std::cerr << "Peer not found" << std::endl;
                continue;
            }

            Peer& peer = discoveredPeers[peerName];
            int sock = connectToPeer(peer.ip, peer.port);
            if (sock < 0) continue;

            std::string message;
            std::cout << "Enter message: ";
            std::getline(std::cin, message);

            // Send raw for now
            send(sock, message.c_str(), message.size(), 0);

            // Receive raw reply
            char buffer[4096];
            int bytesRead = recv(sock, buffer, sizeof(buffer), 0);
            if (bytesRead > 0) {
                std::cout << "Reply: " << std::string(buffer, bytesRead) << std::endl;
            }

            closeConnection(sock);

        } else if (input == "quit") {
            break;

        } else {
            std::cout << "Commands: list, send, quit" << std::endl;
        }
    }

    DNSServiceRefDeallocate(registerRef);
    DNSServiceRefDeallocate(browseRef);
    return 0;
}