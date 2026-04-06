#include "mdns.h"
#include "network.h"
#include "protocol.h"
#include "crypto.h"
#include "filemanager.h"
#include <iostream>
#include <thread>
#include <map>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <queue>
#include <condition_variable>
#include <functional>

// Pending consent request -- server thread posts these, main thread processes them
struct ConsentRequest {
    std::string from;
    std::string filename;
    int64_t filesize;         // for CONSENT_REQUEST (incoming push)
    int clientSocket;         // socket to respond on
    bool isFileRequest;       // true = FILE_REQUEST, false = CONSENT_REQUEST
};

std::queue<ConsentRequest> pendingConsents;
std::mutex consentMutex;
std::condition_variable consentCV;

// Helper: send a message encrypted under session key, or plaintext if no session key
// When encrypted, sends ONLY the raw ciphertext -- no JSON wrapper, no type field
void sendSecure(int socket, const std::string& msg, const std::string& myName,
                const std::string& peerName,
                std::map<std::string, std::string>& sessionKeys, std::mutex& sessionKeysMutex) {
    std::string sessKey;
    {
        std::lock_guard<std::mutex> lock(sessionKeysMutex);
        if (sessionKeys.count(peerName) && !sessionKeys[peerName].empty())
            sessKey = sessionKeys[peerName];
    }
    if (!sessKey.empty()) {
        // Send raw ciphertext only -- no JSON wrapper
        std::string encrypted = aesGcmEncrypt(sessKey, msg);
        sendMessage(socket, encrypted);
    } else {
        sendMessage(socket, msg);
    }
}

// Helper: receive and decrypt a message if encrypted, or return as-is
// After handshake, all messages are raw ciphertext (not JSON)
std::string receiveSecure(int socket, const std::string& peerName,
                          std::map<std::string, std::string>& sessionKeys, std::mutex& sessionKeysMutex) {
    std::string raw = receiveMessage(socket);
    if (raw.empty()) return "";

    // Try to parse as JSON first -- if it works, it's an unencrypted message (EKE/STS/legacy)
    try {
        json test = json::parse(raw);
        if (test.contains("type")) {
            return raw; // Valid JSON with type field -- not encrypted
        }
    } catch (...) {}

    // Not valid JSON -- must be raw ciphertext, try to decrypt
    std::string sessKey;
    {
        std::lock_guard<std::mutex> lock(sessionKeysMutex);
        if (sessionKeys.count(peerName) && !sessionKeys[peerName].empty())
            sessKey = sessionKeys[peerName];
    }
    if (sessKey.empty()) {
        std::cerr << "Received encrypted message but no session key for " << peerName << std::endl;
        return "";
    }
    std::string decrypted = aesGcmDecrypt(sessKey, raw);
    if (decrypted.empty()) {
        std::cerr << "Failed to decrypt message from " << peerName << std::endl;
        return "";
    }
    return decrypted;
}

int main(int argc, char* argv[]) {
    // Usage: ./p2pclient [name] [port]
    // Defaults: name = "Cameron Mac", port = 5001
    std::string myName = (argc > 1) ? argv[1] : "Cameron Mac";
    uint16_t myPort = (argc > 2) ? std::stoi(argv[2]) : 5001;
    std::string keyDir = std::string(getenv("HOME")) + "/.p2pclient-" + std::to_string(myPort);

    std::cout << "Starting P2P client as \"" << myName << "\" on port " << myPort << "..." << std::endl;

    // Set base directory for file manager
    setBaseDir(keyDir);

    // Step 0: Device passphrase for secure local storage
    std::string devicePassphrase;
    std::cout << "Enter device passphrase (for local file encryption): ";
    std::getline(std::cin, devicePassphrase);
    if (devicePassphrase.empty()) {
        std::cerr << "Passphrase cannot be empty. Exiting." << std::endl;
        return 1;
    }

    // Step 1: Load or generate RSA keys
    KeyPair myKeys = loadKeysFromDisk(keyDir);
    if (myKeys.pkey == nullptr) {
        std::cout << "No existing keys found. Generating new RSA 2048-bit key pair..." << std::endl;
        myKeys = generateKeyPair();
        if (myKeys.pkey == nullptr) {
            std::cerr << "Failed to generate keys. Exiting." << std::endl;
            return 1;
        }
        saveKeysToDisk(myKeys, keyDir);
        std::cout << "Keys saved to " << keyDir << std::endl;
    } else {
        std::cout << "Loaded existing keys from " << keyDir << std::endl;
    }
    std::string myPublicKeyPEM = exportPublicKeyPEM(myKeys);

    // Peer public keys (protected by mutex since server thread + main thread both access)
    std::map<std::string, EVP_PKEY*> peerPublicKeys;
    std::mutex peerKeysMutex;

    // Per-peer AES-256 session keys derived from DH exchange (32 bytes each)
    std::map<std::string, std::string> sessionKeys;
    std::mutex sessionKeysMutex;

    // Pre-shared passwords for EKE (peer name -> password)
    std::map<std::string, std::string> peerPasswords;
    std::mutex passwordsMutex;

    // Load passwords from disk
    std::string passwordsFile = keyDir + "/passwords.json";
    if (std::filesystem::exists(passwordsFile)) {
        std::ifstream pf(passwordsFile);
        json pwJson = json::parse(pf);
        for (auto& [name, pw] : pwJson.items()) {
            peerPasswords[name] = pw.get<std::string>();
        }
        std::cout << "Loaded " << peerPasswords.size() << " peer password(s)" << std::endl;
    }

    // Helper to save passwords
    auto savePasswords = [&]() {
        json pwJson;
        for (auto& [name, pw] : peerPasswords) {
            pwJson[name] = pw;
        }
        std::ofstream out(passwordsFile);
        out << pwJson.dump(2);
        out.close();
        std::filesystem::permissions(passwordsFile,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
    };

    // Load any previously saved peer keys
    std::string knownKeysDir = keyDir + "/known_keys";
    if (std::filesystem::exists(knownKeysDir)) {
        for (const auto& entry : std::filesystem::directory_iterator(knownKeysDir)) {
            if (entry.path().extension() == ".pem") {
                std::ifstream file(entry.path());
                std::string pem((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
                EVP_PKEY* key = importPublicKeyPEM(pem);
                if (key) {
                    std::string name = entry.path().stem().string();
                    peerPublicKeys[name] = key;
                    std::cout << "Loaded known key for: " << name << std::endl;
                }
            }
        }
    }

    // Step 2: Start TCP server
    int server = startServer(myPort);
    if (server < 0) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    // Step 2: Register on mDNS
    auto registerRef = registerPeer(myName, myPort);
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
    std::thread serverThread([&]() {
        while (true) {
            sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientSocket = accept(server, (sockaddr*)&clientAddr, &clientLen);

            if (clientSocket < 0) continue;

            std::cout << "\nPeer connected!" << std::endl;

            // Read length-prefixed JSON message
            std::string raw = receiveMessage(clientSocket);
            if (raw.empty()) {
                std::cout << "No data received" << std::endl;
                closeConnection(clientSocket);
                std::cout << "> ";
                std::flush(std::cout);
                continue;
            }

            try {
                // Try to parse as JSON -- if it fails, it's raw ciphertext
                json msg;
                try {
                    msg = json::parse(raw);
                } catch (...) {
                    // Not valid JSON -- try to decrypt as raw ciphertext
                    // We need to try all session keys since we don't know who sent it
                    std::string decrypted;
                    std::lock_guard<std::mutex> lock(sessionKeysMutex);
                    for (auto& [name, key] : sessionKeys) {
                        if (key.empty()) continue;
                        decrypted = aesGcmDecrypt(key, raw);
                        if (!decrypted.empty()) break;
                    }
                    if (decrypted.empty()) {
                        std::cerr << "Failed to decrypt incoming message" << std::endl;
                        closeConnection(clientSocket);
                        std::cout << "> ";
                        std::flush(std::cout);
                        continue;
                    }
                    msg = json::parse(decrypted);
                }

                std::string type = msg["type"];
                std::string from = msg["from"];

                MessageType msgType = parseMessageType(type);

                switch (msgType) {
                    case MessageType::HANDSHAKE:
                        std::cerr << "[HANDSHAKE] Legacy handshake not supported. Use EKE or STS." << std::endl;
                        sendMessage(clientSocket, buildError(myName, "Use EKE or STS handshake"));
                        break;

                    // --- DH-EKE Responder (Bob role) ---
                    case MessageType::EKE_1: {
                        std::cout << "[EKE] Starting DH-EKE handshake with " << from << std::endl;

                        // Look up password for this peer
                        std::string password;
                        {
                            std::lock_guard<std::mutex> lock(passwordsMutex);
                            if (peerPasswords.count(from)) password = peerPasswords[from];
                        }
                        if (password.empty()) {
                            std::cerr << "  No password set for " << from << std::endl;
                            sendMessage(clientSocket, buildError(myName, "No pre-shared password"));
                            break;
                        }

                        // Derive password key W
                        std::string W = deriveEKEKey(password, myName, from);
                        if (W.empty()) break;

                        // Decrypt peer's DH public key
                        std::string peerRawDH = aesGcmDecrypt(W, msg["c1"].get<std::string>());
                        if (peerRawDH.empty() || peerRawDH.size() != 256) {
                            std::cerr << "  EKE failed: wrong password or tampered message" << std::endl;
                            sendMessage(clientSocket, buildError(myName, "Authentication failed"));
                            break;
                        }

                        // Generate our DH key pair
                        DHKeyPair myDH = generateDHKeyPair();
                        std::string myRawDH = exportDHPublicKeyRaw(myDH);

                        // Derive session key K
                        std::string K = deriveSessionKeyFromRaw(myDH, peerRawDH);
                        if (K.empty()) { freeDHKeyPair(myDH); break; }

                        // Generate challenge r_B
                        std::string r_B = generateChallenge();

                        // Send EKE_2: enc_w(our DH pub) + enc_K(r_B)
                        std::string c2 = aesGcmEncrypt(W, myRawDH);
                        std::string c3 = aesGcmEncrypt(K, r_B);
                        sendMessage(clientSocket, buildEKE2(myName, c2, c3));

                        // Receive EKE_3
                        std::string raw3 = receiveMessage(clientSocket);
                        if (raw3.empty()) { freeDHKeyPair(myDH); break; }
                        json msg3 = parseMessage(raw3);

                        // Decrypt c4 and validate
                        std::string plaintext3 = aesGcmDecrypt(K, msg3["c4"].get<std::string>());
                        if (plaintext3.size() < 32) {
                            std::cerr << "  EKE failed: invalid EKE_3 message" << std::endl;
                            freeDHKeyPair(myDH);
                            break;
                        }

                        std::string r_A = plaintext3.substr(0, 16);
                        std::string r_B_echo = plaintext3.substr(16, 16);
                        std::string peerRSAPEM = plaintext3.substr(32);

                        // Verify r_B matches (constant-time comparison)
                        if (CRYPTO_memcmp(r_B.data(), r_B_echo.data(), 16) != 0) {
                            std::cerr << "  EKE FAILED: challenge mismatch (wrong password or MITM)" << std::endl;
                            freeDHKeyPair(myDH);
                            break;
                        }

                        // Store peer's RSA public key
                        EVP_PKEY* peerRSAKey = importPublicKeyPEM(peerRSAPEM);
                        if (peerRSAKey) {
                            std::lock_guard<std::mutex> lock(peerKeysMutex);
                            if (peerPublicKeys.count(from) && peerPublicKeys[from])
                                EVP_PKEY_free(peerPublicKeys[from]);
                            peerPublicKeys[from] = peerRSAKey;
                            std::filesystem::create_directories(knownKeysDir);
                            std::ofstream out(knownKeysDir + "/" + from + ".pem");
                            out << peerRSAPEM;
                            out.close();
                        }

                        // Send EKE_4: enc_K(r_A + our RSA pub)
                        std::string payload4 = r_A + myPublicKeyPEM;
                        std::string c5 = aesGcmEncrypt(K, payload4);
                        sendMessage(clientSocket, buildEKE4(myName, c5));

                        // Store session key
                        {
                            std::lock_guard<std::mutex> lock(sessionKeysMutex);
                            sessionKeys[from] = K;
                        }

                        std::cout << "  EKE handshake complete with " << from << std::endl;
                        freeDHKeyPair(myDH);
                        break;
                    }

                    // --- STS Responder (Bob role) ---
                    case MessageType::STS_1: {
                        std::cout << "[STS] Starting STS handshake with " << from << std::endl;

                        std::string peerDHPubB64 = msg["dh_public_key"].get<std::string>();

                        // Check we have a trusted key for this peer
                        EVP_PKEY* peerRSAKey = nullptr;
                        {
                            std::lock_guard<std::mutex> lock(peerKeysMutex);
                            if (peerPublicKeys.count(from)) peerRSAKey = peerPublicKeys[from];
                        }
                        if (!peerRSAKey) {
                            std::cerr << "  No trusted key for " << from << ". Use EKE first." << std::endl;
                            sendMessage(clientSocket, buildError(myName, "No trusted key. Use EKE handshake first."));
                            break;
                        }

                        // Generate our DH key pair
                        DHKeyPair myDH = generateDHKeyPair();
                        std::string myDHPubB64 = exportDHPublicKey(myDH);

                        // Derive session key K
                        std::string K = deriveSessionKey(myDH, peerDHPubB64);
                        if (K.empty()) { freeDHKeyPair(myDH); break; }

                        // Sign: sig_Bob(myDH || peerDH)
                        std::string sigData = myDHPubB64 + peerDHPubB64;
                        std::string sig = rsaPssSign(myKeys, sigData);
                        std::string encSig = aesGcmEncrypt(K, sig);

                        // Send STS_2
                        sendMessage(clientSocket, buildSTS2(myName, myDHPubB64, encSig));

                        // Receive STS_3
                        std::string raw3 = receiveMessage(clientSocket);
                        if (raw3.empty()) { freeDHKeyPair(myDH); break; }
                        json msg3 = parseMessage(raw3);

                        // Verify peer's signature
                        std::string peerSig = aesGcmDecrypt(K, msg3["encrypted_signature"].get<std::string>());
                        std::string peerSigData = peerDHPubB64 + myDHPubB64;
                        if (!rsaPssVerify(peerRSAKey, peerSigData, peerSig)) {
                            std::cerr << "  STS FAILED: signature verification failed" << std::endl;
                            freeDHKeyPair(myDH);
                            break;
                        }

                        // Store session key
                        {
                            std::lock_guard<std::mutex> lock(sessionKeysMutex);
                            sessionKeys[from] = K;
                        }

                        std::cout << "  STS handshake complete with " << from << std::endl;
                        freeDHKeyPair(myDH);
                        break;
                    }

                    // EKE_2/3/4 and STS_2/3 are only received during an active handshake,
                    // not as standalone messages to the server
                    case MessageType::EKE_2:
                    case MessageType::EKE_3:
                    case MessageType::EKE_4:
                    case MessageType::STS_2:
                    case MessageType::STS_3:
                    case MessageType::ENCRYPTED:
                        std::cerr << "Unexpected message: " << type << std::endl;
                        break;

                    case MessageType::FILE_LIST_REQUEST: {
                        std::cout << "[FILE_LIST_REQUEST] from " << from << std::endl;
                        auto files = getSharedFileList(myKeys);
                        std::string reply = buildFileListResponse(myName, files);
                        sendSecure(clientSocket, reply, myName, from, sessionKeys, sessionKeysMutex);
                        std::cout << "  Sent file list (" << files.size() << " files)" << std::endl;
                        break;
                    }

                    case MessageType::FILE_LIST_RESPONSE: {
                        std::cout << "[FILE_LIST_RESPONSE] from " << from << std::endl;
                        auto files = msg["files"].get<std::vector<FileInfo>>();
                        for (const auto& f : files) {
                            std::cout << "  - " << f.name << " (" << f.size << " bytes)" << std::endl;
                        }
                        break;
                    }

                    case MessageType::FILE_REQUEST: {
                        std::string requestedFile = msg["filename"].get<std::string>();
                        std::cout << "\n[FILE_REQUEST] " << from
                                  << " wants to download \"" << requestedFile << "\"" << std::endl;

                        // Check shared folder first, then downloads
                        std::string rawContents = readSharedFile(requestedFile);
                        if (rawContents.empty() && !hasDownloadedFile(requestedFile)) {
                            std::string errMsg = buildError(myName, "File not found: " + requestedFile);
                            sendSecure(clientSocket, errMsg, myName, from, sessionKeys, sessionKeysMutex);
                            break;
                        }

                        // Queue consent request for the main thread
                        {
                            std::lock_guard<std::mutex> lock(consentMutex);
                            pendingConsents.push({from, requestedFile, 0, clientSocket, true});
                        }
                        consentCV.notify_one();
                        std::cout << "  Type 'consent' to accept/reject this request" << std::endl;
                        std::cout << "> ";
                        std::flush(std::cout);

                        // Don't close this socket -- the main thread will respond
                        continue;
                    }

                    case MessageType::CONSENT_REQUEST: {
                        std::string fname = msg["filename"].get<std::string>();
                        int64_t fsize = msg["filesize"].get<int64_t>();
                        std::cout << "\n[CONSENT_REQUEST] " << from
                                  << " wants to send you \"" << fname
                                  << "\" (" << fsize << " bytes)" << std::endl;

                        // Queue for main thread
                        {
                            std::lock_guard<std::mutex> lock(consentMutex);
                            pendingConsents.push({from, fname, fsize, clientSocket, false});
                        }
                        consentCV.notify_one();
                        std::cout << "  Type 'consent' to accept/reject this request" << std::endl;
                        std::cout << "> ";
                        std::flush(std::cout);

                        // Don't close this socket
                        continue;
                    }

                    case MessageType::CONSENT_RESPONSE:
                        std::cout << "[CONSENT_RESPONSE] from " << from
                                  << " for \"" << msg["filename"].get<std::string>() << "\": "
                                  << (msg["accepted"].get<bool>() ? "ACCEPTED" : "REJECTED") << std::endl;
                        break;

                    case MessageType::FILE_TRANSFER: {
                        std::string fname = msg["filename"].get<std::string>();
                        std::cout << "[FILE_TRANSFER] from " << from
                                  << " file \"" << fname << "\"" << std::endl;
                        std::string data = msg["data"].get<std::string>();
                        // Save via base64, read back, then encrypt at rest
                        saveFileFromBase64(fname, data);
                        {
                            std::string tmpPath = getDownloadsDir() + "/" + fname;
                            std::ifstream tmpFile(tmpPath, std::ios::binary);
                            std::string contents((std::istreambuf_iterator<char>(tmpFile)),
                                                  std::istreambuf_iterator<char>());
                            tmpFile.close();
                            std::filesystem::remove(tmpPath);
                            saveFileEncrypted(fname, contents, devicePassphrase);
                        }
                        break;
                    }

                    case MessageType::KEY_ROTATION: {
                        std::cout << "[KEY_ROTATION] from " << from << std::endl;
                        std::string newKeyPEM = msg["new_public_key"].get<std::string>();
                        std::string sig = msg["signature"].get<std::string>();

                        // Verify signature with the OLD key we have on file
                        std::lock_guard<std::mutex> lock(peerKeysMutex);
                        if (peerPublicKeys.count(from) && peerPublicKeys[from]) {
                            if (rsaPssVerify(peerPublicKeys[from], newKeyPEM, sig)) {
                                // Signature valid -- update to new key
                                EVP_PKEY* newKey = importPublicKeyPEM(newKeyPEM);
                                if (newKey) {
                                    EVP_PKEY_free(peerPublicKeys[from]);
                                    peerPublicKeys[from] = newKey;
                                    // Save new key to disk
                                    std::filesystem::create_directories(knownKeysDir);
                                    std::ofstream out(knownKeysDir + "/" + from + ".pem");
                                    out << newKeyPEM;
                                    out.close();
                                    std::cout << "  Key updated for " << from << std::endl;

                                    // Invalidate session key (need new handshake)
                                    std::lock_guard<std::mutex> lock2(sessionKeysMutex);
                                    sessionKeys.erase(from);
                                }
                            } else {
                                std::cerr << "  WARNING: Key rotation signature verification FAILED! Ignoring." << std::endl;
                            }
                        } else {
                            std::cerr << "  No existing key for " << from << " -- cannot verify rotation" << std::endl;
                        }
                        break;
                    }

                    case MessageType::ERROR_MSG:
                        std::cerr << "[ERROR] from " << from << ": "
                                  << msg["message"].get<std::string>() << std::endl;
                        break;
                }
            } catch (const std::exception& e) {
                std::cerr << "Failed to parse message: " << e.what() << std::endl;
            }

            closeConnection(clientSocket);
            std::cout << "> ";
            std::flush(std::cout);
        }
    });
    serverThread.detach();

    
    // Step 6: Command loop
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  list       - Show discovered peers" << std::endl;
    std::cout << "  password   - Set a pre-shared password for a peer (for EKE)" << std::endl;
    std::cout << "  handshake  - Authenticate with a peer (EKE first time, STS after)" << std::endl;
    std::cout << "  files      - Request a peer's file list" << std::endl;
    std::cout << "  request    - Request a file from a peer" << std::endl;
    std::cout << "  consent    - Accept/reject a pending file request" << std::endl;
    std::cout << "  rotate     - Rotate RSA keys and notify peers" << std::endl;
    std::cout << "  quit       - Exit the program" << std::endl;

    std::string input;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);

        if (input == "list") {
            listPeers();

        } else if (input == "handshake") {
            listPeers();
            std::string peerName;
            std::cout << "Enter peer name: ";
            std::getline(std::cin, peerName);

            if (discoveredPeers.find(peerName) == discoveredPeers.end()) {
                std::cerr << "Peer not found" << std::endl;
                continue;
            }

            // Decide: STS (have trusted key) or EKE (have password)
            bool haveTrustedKey = false;
            {
                std::lock_guard<std::mutex> lock(peerKeysMutex);
                haveTrustedKey = peerPublicKeys.count(peerName) && peerPublicKeys[peerName];
            }

            Peer& peer = discoveredPeers[peerName];
            int sock = connectToPeer(peer.ip, peer.port);
            if (sock < 0) continue;

            if (haveTrustedKey) {
                // --- STS Initiator (Alice role) ---
                std::cout << "Using STS (trusted key exists)" << std::endl;

                DHKeyPair myDH = generateDHKeyPair();
                std::string myDHPubB64 = exportDHPublicKey(myDH);

                // Send STS_1
                sendMessage(sock, buildSTS1(myName, myDHPubB64));

                // Receive STS_2
                std::string reply = receiveMessage(sock);
                if (reply.empty()) { freeDHKeyPair(myDH); closeConnection(sock); continue; }

                try {
                    json resp = parseMessage(reply);
                    if (resp["type"] == "ERROR") {
                        std::cerr << "Error: " << resp["message"].get<std::string>() << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }

                    std::string peerDHPubB64 = resp["dh_public_key"].get<std::string>();
                    std::string K = deriveSessionKey(myDH, peerDHPubB64);

                    // Verify peer's signature
                    std::string peerSig = aesGcmDecrypt(K, resp["encrypted_signature"].get<std::string>());
                    std::string peerSigData = peerDHPubB64 + myDHPubB64;

                    EVP_PKEY* peerRSAKey = nullptr;
                    {
                        std::lock_guard<std::mutex> lock(peerKeysMutex);
                        peerRSAKey = peerPublicKeys[peerName];
                    }

                    if (!rsaPssVerify(peerRSAKey, peerSigData, peerSig)) {
                        std::cerr << "STS FAILED: peer signature verification failed" << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }
                    std::cout << "Peer identity verified (STS signature OK)" << std::endl;

                    // Send STS_3: our signature
                    std::string mySigData = myDHPubB64 + peerDHPubB64;
                    std::string mySig = rsaPssSign(myKeys, mySigData);
                    std::string encSig = aesGcmEncrypt(K, mySig);
                    sendMessage(sock, buildSTS3(myName, encSig));

                    // Store session key
                    {
                        std::lock_guard<std::mutex> lock(sessionKeysMutex);
                        sessionKeys[peerName] = K;
                    }
                    std::cout << "STS handshake complete. Session key established with " << peerName << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "STS failed: " << e.what() << std::endl;
                }
                freeDHKeyPair(myDH);

            } else {
                // --- EKE Initiator (Alice role) ---
                std::string password;
                {
                    std::lock_guard<std::mutex> lock(passwordsMutex);
                    if (peerPasswords.count(peerName)) password = peerPasswords[peerName];
                }
                if (password.empty()) {
                    std::cerr << "No trusted key and no password for " << peerName << std::endl;
                    std::cerr << "Set a password first with the 'password' command" << std::endl;
                    closeConnection(sock);
                    continue;
                }

                std::cout << "Using DH-EKE (first-time handshake)" << std::endl;

                // Derive password key W
                std::string W = deriveEKEKey(password, myName, peerName);
                if (W.empty()) { closeConnection(sock); continue; }

                // Generate DH key pair, encrypt with W
                DHKeyPair myDH = generateDHKeyPair();
                std::string myRawDH = exportDHPublicKeyRaw(myDH);
                std::string c1 = aesGcmEncrypt(W, myRawDH);

                // Send EKE_1
                sendMessage(sock, buildEKE1(myName, c1));

                // Receive EKE_2
                std::string reply = receiveMessage(sock);
                if (reply.empty()) { freeDHKeyPair(myDH); closeConnection(sock); continue; }

                try {
                    json resp = parseMessage(reply);
                    if (resp["type"] == "ERROR") {
                        std::cerr << "Error: " << resp["message"].get<std::string>() << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }

                    // Decrypt peer's DH public key
                    std::string peerRawDH = aesGcmDecrypt(W, resp["c2"].get<std::string>());
                    if (peerRawDH.empty() || peerRawDH.size() != 256) {
                        std::cerr << "EKE failed: wrong password or tampered message" << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }

                    // Derive session key K
                    std::string K = deriveSessionKeyFromRaw(myDH, peerRawDH);
                    if (K.empty()) { freeDHKeyPair(myDH); closeConnection(sock); continue; }

                    // Decrypt challenge r_B
                    std::string r_B = aesGcmDecrypt(K, resp["c3"].get<std::string>());
                    if (r_B.empty()) { freeDHKeyPair(myDH); closeConnection(sock); continue; }

                    // Generate our challenge r_A
                    std::string r_A = generateChallenge();

                    // Send EKE_3: enc_K(r_A || r_B || RSA_pub)
                    std::string payload3 = r_A + r_B + myPublicKeyPEM;
                    std::string c4 = aesGcmEncrypt(K, payload3);
                    sendMessage(sock, buildEKE3(myName, c4));

                    // Receive EKE_4
                    std::string reply4 = receiveMessage(sock);
                    if (reply4.empty()) { freeDHKeyPair(myDH); closeConnection(sock); continue; }

                    json resp4 = parseMessage(reply4);
                    std::string plaintext4 = aesGcmDecrypt(K, resp4["c5"].get<std::string>());
                    if (plaintext4.size() < 16) {
                        std::cerr << "EKE failed: invalid EKE_4" << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }

                    // Verify r_A echo (constant-time)
                    std::string r_A_echo = plaintext4.substr(0, 16);
                    if (CRYPTO_memcmp(r_A.data(), r_A_echo.data(), 16) != 0) {
                        std::cerr << "EKE FAILED: challenge mismatch (wrong password or MITM)" << std::endl;
                        freeDHKeyPair(myDH); closeConnection(sock); continue;
                    }

                    // Extract and store peer's RSA public key
                    std::string peerRSAPEM = plaintext4.substr(16);
                    EVP_PKEY* peerRSAKey = importPublicKeyPEM(peerRSAPEM);
                    if (peerRSAKey) {
                        std::lock_guard<std::mutex> lock(peerKeysMutex);
                        if (peerPublicKeys.count(peerName) && peerPublicKeys[peerName])
                            EVP_PKEY_free(peerPublicKeys[peerName]);
                        peerPublicKeys[peerName] = peerRSAKey;
                        std::filesystem::create_directories(knownKeysDir);
                        std::ofstream out(knownKeysDir + "/" + peerName + ".pem");
                        out << peerRSAPEM;
                        out.close();
                    }

                    // Store session key
                    {
                        std::lock_guard<std::mutex> lock(sessionKeysMutex);
                        sessionKeys[peerName] = K;
                    }

                    std::cout << "EKE handshake complete. RSA key and session key established with " << peerName << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "EKE failed: " << e.what() << std::endl;
                }
                freeDHKeyPair(myDH);
            }

            closeConnection(sock);

        } else if (input == "files") {
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

            // Send FILE_LIST_REQUEST (encrypted if session key exists)
            std::string msg = buildFileListRequest(myName);
            sendSecure(sock, msg, myName, peerName, sessionKeys, sessionKeysMutex);

            // Wait for FILE_LIST_RESPONSE
            std::string reply = receiveSecure(sock, peerName, sessionKeys, sessionKeysMutex);
            if (reply.empty()) {
                std::cerr << "ERROR: No response from peer. Connection may have been lost." << std::endl;
            } else {
                try {
                    json response = parseMessage(reply);
                    if (response["type"] == "FILE_LIST_RESPONSE") {
                        auto files = response["files"].get<std::vector<FileInfo>>();
                        if (files.empty()) {
                            std::cout << "No files available from " << peerName << std::endl;
                        } else {
                            std::cout << "Files available from " << peerName << ":" << std::endl;
                            for (const auto& f : files) {
                                std::cout << "  - " << f.name << " (" << f.size << " bytes)" << std::endl;
                            }
                        }
                    } else if (response["type"] == "ERROR") {
                        std::cerr << "ERROR: " << response["message"].get<std::string>() << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "ERROR: Failed to parse response: " << e.what() << std::endl;
                }
            }

            closeConnection(sock);

        } else if (input == "request") {
            listPeers();
            std::string peerName;
            std::cout << "Enter peer name: ";
            std::getline(std::cin, peerName);

            if (discoveredPeers.find(peerName) == discoveredPeers.end()) {
                std::cerr << "Peer not found" << std::endl;
                continue;
            }

            std::string filename;
            std::cout << "Enter filename: ";
            std::getline(std::cin, filename);

            Peer& peer = discoveredPeers[peerName];
            int sock = connectToPeer(peer.ip, peer.port);
            if (sock < 0) continue;

            // Send FILE_REQUEST (encrypted if session key exists)
            std::string msg = buildFileRequest(myName, filename);
            sendSecure(sock, msg, myName, peerName, sessionKeys, sessionKeysMutex);

            // Wait for FILE_TRANSFER or ERROR response
            std::string reply = receiveSecure(sock, peerName, sessionKeys, sessionKeysMutex);
            if (reply.empty()) {
                std::cerr << "ERROR: No response from peer. File could not be delivered." << std::endl;
                closeConnection(sock);
                continue;
            }
            if (!reply.empty()) {
                try {
                    json response = parseMessage(reply);
                    std::string respType = response["type"].get<std::string>();
                    if (respType == "FILE_TRANSFER") {
                        std::string data = response["data"].get<std::string>();
                        std::string hash = response["hash"].get<std::string>();
                        std::string sig = response["signature"].get<std::string>();
                        std::string senderName = response["from"].get<std::string>();
                        std::string originalOwner = response.contains("original_owner")
                            ? response["original_owner"].get<std::string>() : senderName;

                        // Message was already decrypted by receiveSecure
                        // Data field contains base64-encoded file contents
                        std::string fileContents;
                        saveFileFromBase64(filename, data);
                        std::string tmpPath = getDownloadsDir() + "/" + filename;
                        std::ifstream tmpFile(tmpPath, std::ios::binary);
                        fileContents = std::string((std::istreambuf_iterator<char>(tmpFile)),
                                                    std::istreambuf_iterator<char>());
                        tmpFile.close();
                        std::filesystem::remove(tmpPath);

                        // Step 2: Verify integrity (hash)
                        bool hashOk = false;
                        bool sigOk = false;
                        std::string computedHash = sha256Hash(fileContents);
                        if (computedHash != hash) {
                            std::cerr << "SECURITY WARNING: File has been tampered with in transit!" << std::endl;
                            std::cerr << "  Expected hash: " << hash.substr(0, 32) << "..." << std::endl;
                            std::cerr << "  Computed hash: " << computedHash.substr(0, 32) << "..." << std::endl;
                        } else {
                            std::cout << "File integrity verified (hash matches)" << std::endl;
                            hashOk = true;
                        }

                        // Step 3: Verify authenticity (signature)
                        if (hashOk) {
                            std::lock_guard<std::mutex> lock(peerKeysMutex);
                            if (peerPublicKeys.count(originalOwner) && peerPublicKeys[originalOwner]) {
                                if (rsaPssVerify(peerPublicKeys[originalOwner], hash, sig)) {
                                    sigOk = true;
                                    if (originalOwner != senderName) {
                                        std::cout << "File authenticity verified (original owner: " << originalOwner
                                                  << ", delivered by: " << senderName << ")" << std::endl;
                                    } else {
                                        std::cout << "File authenticity verified (valid signature from " << originalOwner << ")" << std::endl;
                                    }
                                } else {
                                    std::cerr << "SECURITY WARNING: File signature verification FAILED!" << std::endl;
                                    std::cerr << "  The file may not be from " << originalOwner << " or has been modified." << std::endl;
                                }
                            } else {
                                std::cerr << "WARNING: No public key for " << originalOwner << " -- cannot verify file authenticity." << std::endl;
                            }
                        }

                        // Step 4: Ask user if they want to save
                        if (!hashOk || !sigOk) {
                            std::cout << "Save file anyway? (y/n): ";
                            std::string answer;
                            std::getline(std::cin, answer);
                            if (answer != "y" && answer != "Y") {
                                std::cout << "File discarded." << std::endl;
                                closeConnection(sock);
                                continue;
                            }
                        }

                        // Step 5: Save encrypted at rest
                        saveFileEncrypted(filename, fileContents, devicePassphrase);
                        saveFileMeta(filename, originalOwner, hash, sig);
                    } else if (respType == "CONSENT_RESPONSE") {
                        bool accepted = response["accepted"].get<bool>();
                        if (!accepted) {
                            std::cout << "File request was rejected by " << response["from"].get<std::string>() << std::endl;
                        }
                    } else if (respType == "ERROR") {
                        std::cerr << "Error: " << response["message"].get<std::string>() << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Failed to parse response: " << e.what() << std::endl;
                }
            }

            closeConnection(sock);

        } else if (input == "consent") {
            ConsentRequest cr;
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(consentMutex);
                if (!pendingConsents.empty()) {
                    cr = pendingConsents.front();
                    pendingConsents.pop();
                    found = true;
                }
            }

            if (!found) {
                std::cout << "No pending consent requests" << std::endl;
                continue;
            }

            if (cr.isFileRequest) {
                std::cout << cr.from << " wants to download \"" << cr.filename << "\". Allow? (y/n): ";
            } else {
                std::cout << cr.from << " wants to send you \"" << cr.filename
                          << "\" (" << cr.filesize << " bytes). Accept? (y/n): ";
            }
            std::string answer;
            std::getline(std::cin, answer);
            bool accepted = (answer == "y" || answer == "Y");

            if (cr.isFileRequest) {
                if (accepted) {
                    std::string rawContents = readSharedFile(cr.filename);
                    std::string hash, signature, originalOwner;

                    if (!rawContents.empty()) {
                        hash = sha256Hash(rawContents);
                        signature = rsaPssSign(myKeys, hash);
                        originalOwner = myName;
                    } else if (hasDownloadedFile(cr.filename)) {
                        rawContents = readDownloadedFile(cr.filename, devicePassphrase);
                        if (rawContents.empty()) {
                            sendSecure(cr.clientSocket, buildError(myName, "Failed to read file"), myName, cr.from, sessionKeys, sessionKeysMutex);
                            closeConnection(cr.clientSocket);
                            continue;
                        }
                        if (!loadFileMeta(cr.filename, originalOwner, hash, signature)) {
                            hash = sha256Hash(rawContents);
                            signature = rsaPssSign(myKeys, hash);
                            originalOwner = myName;
                        }
                    } else {
                        sendSecure(cr.clientSocket, buildError(myName, "File not found: " + cr.filename), myName, cr.from, sessionKeys, sessionKeysMutex);
                        closeConnection(cr.clientSocket);
                        continue;
                    }

                    // Base64 encode file data for the JSON message
                    // The entire message will be encrypted by sendSecure
                    std::string fileData = readFileBase64(cr.filename);
                    if (fileData.empty() && !rawContents.empty()) {
                        // Downloaded file -- base64 encode raw contents manually
                        // Use a simple approach: write to temp, read as base64
                        // Actually, we can just put raw contents and let sendSecure encrypt everything
                        fileData = rawContents; // Will be inside encrypted envelope
                    }

                    std::string reply = buildFileTransfer(myName, cr.filename, fileData, hash, signature, originalOwner);
                    sendSecure(cr.clientSocket, reply, myName, cr.from, sessionKeys, sessionKeysMutex);
                    std::cout << "Sent file: " << cr.filename << " (original owner: " << originalOwner << ")" << std::endl;
                } else {
                    std::string reply = buildConsentResponse(myName, cr.filename, false);
                    sendSecure(cr.clientSocket, reply, myName, cr.from, sessionKeys, sessionKeysMutex);
                    std::cout << "Rejected file request" << std::endl;
                }
            } else {
                std::string reply = buildConsentResponse(myName, cr.filename, accepted);
                sendSecure(cr.clientSocket, reply, myName, cr.from, sessionKeys, sessionKeysMutex);
            }
            closeConnection(cr.clientSocket);

        } else if (input == "password") {
            std::string peerName;
            std::cout << "Enter peer name: ";
            std::getline(std::cin, peerName);
            std::string pw;
            std::cout << "Enter shared password: ";
            std::getline(std::cin, pw);
            {
                std::lock_guard<std::mutex> lock(passwordsMutex);
                peerPasswords[peerName] = pw;
                savePasswords();
            }
            std::cout << "Password saved for " << peerName << std::endl;

        } else if (input == "rotate") {
            std::cout << "Generating new RSA 2048-bit key pair..." << std::endl;

            // Sign the new public key with the OLD private key
            KeyPair newKeys = generateKeyPair();
            if (newKeys.pkey == nullptr) {
                std::cerr << "Failed to generate new keys" << std::endl;
                continue;
            }
            std::string newPublicKeyPEM = exportPublicKeyPEM(newKeys);
            std::string signature = rsaPssSign(myKeys, newPublicKeyPEM);

            // Replace our keys
            freeKeyPair(myKeys);
            myKeys = newKeys;
            myPublicKeyPEM = newPublicKeyPEM;
            saveKeysToDisk(myKeys, keyDir);
            std::cout << "New keys saved to " << keyDir << std::endl;

            // Invalidate all session keys (peers need to re-handshake)
            {
                std::lock_guard<std::mutex> lock(sessionKeysMutex);
                sessionKeys.clear();
            }

            // Broadcast KEY_ROTATION to all discovered peers
            std::string rotateMsg = buildKeyRotation(myName, newPublicKeyPEM, signature);
            int notified = 0;
            for (auto& [name, peer] : discoveredPeers) {
                if (name == myName) continue;
                int sock = connectToPeer(peer.ip, peer.port);
                if (sock < 0) continue;
                sendMessage(sock, rotateMsg);
                closeConnection(sock);
                notified++;
            }
            std::cout << "Key rotation complete. Notified " << notified << " peer(s)." << std::endl;

        } else if (input == "quit") {
            break;

        } else {
            std::cout << "Commands: list, password, handshake, files, request, consent, rotate, quit" << std::endl;
        }
    }

    // Cleanup
    DNSServiceRefDeallocate(registerRef);
    DNSServiceRefDeallocate(browseRef);
    freeKeyPair(myKeys);
    for (auto& [name, key] : peerPublicKeys) {
        EVP_PKEY_free(key);
    }
    return 0;
}