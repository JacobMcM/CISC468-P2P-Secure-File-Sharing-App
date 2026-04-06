#include "network.h"
#include <iostream>


int startServer(uint16_t port) {
   // Step 1: Create a TCP socket
    int serverSocket = socket(AF_INET /* IPv4 */, SOCK_STREAM /* TCP */, 0 /* default protocol */);
    if (serverSocket < 0) {
           std::cerr << "Failed to create socket" << std::endl;
       return -1;
   }


   // Step 2: Allow reusing the port if the program restarts quickly
   int opt = 1;
   #ifdef _WIN32
       setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
   #else
       setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   #endif


   // Step 3: Set up the address — listen on all interfaces at the given port
   sockaddr_in addr{};
   addr.sin_family = AF_INET;         // IPv4
   addr.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP
   addr.sin_port = htons(port);       // Convert port to network byte order


   // Step 4: Bind the socket to the address and port
   if (bind(serverSocket, (sockaddr*)&addr, sizeof(addr)) < 0) {
       std::cerr << "Failed to bind to port " << port << std::endl;
       close(serverSocket);
       return -1;
   }


   // Step 5: Start listening for incoming connections (queue up to 5)
   if (listen(serverSocket, 5) < 0) {
       std::cerr << "Failed to listen" << std::endl;
       close(serverSocket);
       return -1;
   }


   std::cout << "Server listening on port " << port << std::endl;
   return serverSocket;
}


int connectToPeer(const std::string& ip, uint16_t port) {
    // Step 1: Create a TCP socket
    int sock = socket(AF_INET /* IPv4 */, SOCK_STREAM /* TCP */, 0 /* default protocol */);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return -1;
    }

    // Step 2: Set up the peer's address
    sockaddr_in addr{};
    addr.sin_family = AF_INET;                        // IPv4
    addr.sin_port = htons(port);                      // Convert port to network byte order
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);   // Convert IP string to binary

    // Step 3: Connect to the peer
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to connect to " << ip << ":" << port << std::endl;
        close(sock);
        return -1;
    }

    std::cout << "Connected to " << ip << ":" << port << std::endl;
    return sock;
}


bool sendMessage(int socket, const std::string& message) {
    /*

    This uses **length-prefixing** — before sending the message, you send 4 bytes telling the receiver how long the message is. Without this, the receiver wouldn't know where one message ends and the next begins.

    **`htonl`** is like `htons` but for 32-bit integers instead of 16-bit. The "l" stands for "long." Converts the length to network byte order so all three clients read it the same way.

    **`send()`** sends data over the socket. It takes the socket, a pointer to the data, the size, and flags (0 means no special flags).

    So the data on the wire looks like:

    [4 bytes: message length][actual message bytes]
    */

    // Step 1: Get the message length and convert to network byte order
    uint32_t length = htonl(message.size());

    // Step 2: Send the length first (4 bytes)
    if (send(socket, &length, sizeof(length), 0) < 0) {
        std::cerr << "Failed to send message length" << std::endl;
        return false;
    }

    // Step 3: Send the actual message
    if (send(socket, message.c_str(), message.size(), 0) < 0) {
        std::cerr << "Failed to send message" << std::endl;
        return false;
    }

    return true;

}


std::string receiveMessage(int socket) {
    /*
    This is the mirror of `sendMessage`:

    **`recv()`** — reads data from the socket. Opposite of `send()`.

    **`ntohl()`** — opposite of `htonl()`. Converts the length from network byte order back to your CPU's format. "Network to host long."

    **The while loop** — `recv()` doesn't guarantee it reads everything in one call. If the message is large, it might come in chunks. The loop keeps reading until we've received all `length` bytes. Without this, you could get half a message and think it's the whole thing.

    So the flow matches `sendMessage`:
    ```
    sendMessage:                    receiveMessage:
    1. htonl(length)         →     1. recv 4 bytes, ntohl(length)
    2. send length            →     2. recv message until totalRead == length
    3. send message
    */

    // Step 1: Read the message length (first 4 bytes)
    uint32_t length;
    if (recv(socket, &length, sizeof(length), 0) <= 0) {
        std::cerr << "Failed to receive message length" << std::endl;
        return "";
    }
    length = ntohl(length); // Convert from network byte order back to host

    // Step 2: Read the actual message based on the length
    std::string message(length, '\0'); // Create a string of the right size
    size_t totalRead = 0;

    while (totalRead < length) {
        int bytesRead = recv(socket, &message[totalRead], length - totalRead, 0);
        if (bytesRead <= 0) {
            std::cerr << "Failed to receive message" << std::endl;
            return "";
        }
        totalRead += bytesRead;
    }

    return message;
}


void closeConnection(int socket) {
    #ifdef _WIN32
        closesocket(socket); // Windows uses closesocket()
    #else
        close(socket);       // macOS/Linux uses close()
    #endif
}
   