#ifndef NETWORK_H
#define NETWORK_H

#ifdef _WIN32 // Platform-specific networking headers
    #include <winsock2.h>   // Windows sockets
    #include <ws2tcpip.h>   // Windows TCP/IP functions
#else // macOS/Linux networking (split across multiple headers)
    #include <sys/socket.h> // Socket creation and operations
    #include <netinet/in.h> // Internet address structures
    #include <arpa/inet.h>  // IP conversion functions
    #include <unistd.h>     // close() for sockets
#endif

#include <string>

// Start listening for incoming connections on a port
int startServer(uint16_t port);

// Connect to a peer at a given IP and port
int connectToPeer(const std::string& ip, uint16_t port);

// Send a message over a connection
bool sendMessage(int socket, const std::string& message);

// Receive a message from a connection
std::string receiveMessage(int socket);

// Close a connection
void closeConnection(int socket);

#endif
