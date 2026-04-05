#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "json.hpp"
#include <string>
#include <vector>

using json = nlohmann::json;

// File metadata included in file list responses and transfers
struct FileInfo {
    std::string name;
    int64_t size;
    std::string hash;      // SHA-256 hex string
    std::string signature; // RSA-PSS signature, base64 encoded
};

// Convert FileInfo to/from JSON
inline void to_json(json& j, const FileInfo& f) {
    j = json{
        {"name", f.name},
        {"size", f.size},
        {"hash", f.hash},
        {"signature", f.signature}
    };
}

inline void from_json(const json& j, FileInfo& f) {
    j.at("name").get_to(f.name);
    j.at("size").get_to(f.size);
    j.at("hash").get_to(f.hash);
    j.at("signature").get_to(f.signature);
}

// All protocol message types
enum class MessageType {
    HANDSHAKE,
    EKE_1,
    EKE_2,
    EKE_3,
    EKE_4,
    STS_1,
    STS_2,
    STS_3,
    FILE_LIST_REQUEST,
    FILE_LIST_RESPONSE,
    FILE_REQUEST,
    CONSENT_REQUEST,
    CONSENT_RESPONSE,
    FILE_TRANSFER,
    KEY_ROTATION,
    ERROR_MSG,
    ENCRYPTED
};

// Convert string to MessageType
inline MessageType parseMessageType(const std::string& type) {
    if (type == "HANDSHAKE")          return MessageType::HANDSHAKE;
    if (type == "EKE_1")             return MessageType::EKE_1;
    if (type == "EKE_2")             return MessageType::EKE_2;
    if (type == "EKE_3")             return MessageType::EKE_3;
    if (type == "EKE_4")             return MessageType::EKE_4;
    if (type == "STS_1")             return MessageType::STS_1;
    if (type == "STS_2")             return MessageType::STS_2;
    if (type == "STS_3")             return MessageType::STS_3;
    if (type == "FILE_LIST_REQUEST")  return MessageType::FILE_LIST_REQUEST;
    if (type == "FILE_LIST_RESPONSE") return MessageType::FILE_LIST_RESPONSE;
    if (type == "FILE_REQUEST")       return MessageType::FILE_REQUEST;
    if (type == "CONSENT_REQUEST")    return MessageType::CONSENT_REQUEST;
    if (type == "CONSENT_RESPONSE")   return MessageType::CONSENT_RESPONSE;
    if (type == "FILE_TRANSFER")      return MessageType::FILE_TRANSFER;
    if (type == "KEY_ROTATION")       return MessageType::KEY_ROTATION;
    if (type == "ERROR")              return MessageType::ERROR_MSG;
    if (type == "ENCRYPTED")          return MessageType::ENCRYPTED;
    throw std::runtime_error("Unknown message type: " + type);
}

// Convert MessageType to string
inline std::string messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::HANDSHAKE:          return "HANDSHAKE";
        case MessageType::EKE_1:             return "EKE_1";
        case MessageType::EKE_2:             return "EKE_2";
        case MessageType::EKE_3:             return "EKE_3";
        case MessageType::EKE_4:             return "EKE_4";
        case MessageType::STS_1:             return "STS_1";
        case MessageType::STS_2:             return "STS_2";
        case MessageType::STS_3:             return "STS_3";
        case MessageType::FILE_LIST_REQUEST:  return "FILE_LIST_REQUEST";
        case MessageType::FILE_LIST_RESPONSE: return "FILE_LIST_RESPONSE";
        case MessageType::FILE_REQUEST:       return "FILE_REQUEST";
        case MessageType::CONSENT_REQUEST:    return "CONSENT_REQUEST";
        case MessageType::CONSENT_RESPONSE:   return "CONSENT_RESPONSE";
        case MessageType::FILE_TRANSFER:      return "FILE_TRANSFER";
        case MessageType::KEY_ROTATION:       return "KEY_ROTATION";
        case MessageType::ERROR_MSG:          return "ERROR";
        case MessageType::ENCRYPTED:          return "ENCRYPTED";
    }
    return "UNKNOWN";
}

// --- Message builders (create JSON strings ready to send) ---

// --- DH-EKE messages ---

inline std::string buildEKE1(const std::string& from, const std::string& c1) {
    json j = {{"type", "EKE_1"}, {"from", from}, {"c1", c1}};
    return j.dump();
}

inline std::string buildEKE2(const std::string& from, const std::string& c2, const std::string& c3) {
    json j = {{"type", "EKE_2"}, {"from", from}, {"c2", c2}, {"c3", c3}};
    return j.dump();
}

inline std::string buildEKE3(const std::string& from, const std::string& c4) {
    json j = {{"type", "EKE_3"}, {"from", from}, {"c4", c4}};
    return j.dump();
}

inline std::string buildEKE4(const std::string& from, const std::string& c5) {
    json j = {{"type", "EKE_4"}, {"from", from}, {"c5", c5}};
    return j.dump();
}

// --- STS messages ---

inline std::string buildSTS1(const std::string& from, const std::string& dhPublicKey) {
    json j = {{"type", "STS_1"}, {"from", from}, {"dh_public_key", dhPublicKey}};
    return j.dump();
}

inline std::string buildSTS2(const std::string& from, const std::string& dhPublicKey,
                              const std::string& encryptedSignature) {
    json j = {{"type", "STS_2"}, {"from", from}, {"dh_public_key", dhPublicKey},
              {"encrypted_signature", encryptedSignature}};
    return j.dump();
}

inline std::string buildSTS3(const std::string& from, const std::string& encryptedSignature) {
    json j = {{"type", "STS_3"}, {"from", from}, {"encrypted_signature", encryptedSignature}};
    return j.dump();
}

// --- Legacy HANDSHAKE (kept for compatibility, will be removed) ---

inline std::string buildHandshake(const std::string& from, const std::string& publicKey,
                                  const std::string& dhPublicKey = "",
                                  const std::string& dhSignature = "") {
    json j = {
        {"type", "HANDSHAKE"},
        {"from", from},
        {"public_key", publicKey}
    };
    if (!dhPublicKey.empty()) {
        j["dh_public_key"] = dhPublicKey;
    }
    if (!dhSignature.empty()) {
        j["dh_signature"] = dhSignature;
    }
    return j.dump();
}

// FILE_LIST_REQUEST: ask a peer for their file list
inline std::string buildFileListRequest(const std::string& from) {
    json j = {
        {"type", "FILE_LIST_REQUEST"},
        {"from", from}
    };
    return j.dump();
}

// FILE_LIST_RESPONSE: reply with available files
inline std::string buildFileListResponse(const std::string& from, const std::vector<FileInfo>& files) {
    json j = {
        {"type", "FILE_LIST_RESPONSE"},
        {"from", from},
        {"files", files}
    };
    return j.dump();
}

// FILE_REQUEST: request a specific file
inline std::string buildFileRequest(const std::string& from, const std::string& filename) {
    json j = {
        {"type", "FILE_REQUEST"},
        {"from", from},
        {"filename", filename}
    };
    return j.dump();
}

// CONSENT_REQUEST: ask permission to send a file
inline std::string buildConsentRequest(const std::string& from, const std::string& filename, int64_t filesize) {
    json j = {
        {"type", "CONSENT_REQUEST"},
        {"from", from},
        {"filename", filename},
        {"filesize", filesize}
    };
    return j.dump();
}

// CONSENT_RESPONSE: accept or reject
inline std::string buildConsentResponse(const std::string& from, const std::string& filename, bool accepted) {
    json j = {
        {"type", "CONSENT_RESPONSE"},
        {"from", from},
        {"filename", filename},
        {"accepted", accepted}
    };
    return j.dump();
}

// FILE_TRANSFER: send file data
inline std::string buildFileTransfer(const std::string& from, const std::string& filename,
                                     const std::string& data, const std::string& hash,
                                     const std::string& signature,
                                     const std::string& originalOwner = "") {
    json j = {
        {"type", "FILE_TRANSFER"},
        {"from", from},
        {"filename", filename},
        {"data", data},
        {"hash", hash},
        {"signature", signature}
    };
    if (!originalOwner.empty()) {
        j["original_owner"] = originalOwner;
    }
    return j.dump();
}

// KEY_ROTATION: notify contacts of new key
inline std::string buildKeyRotation(const std::string& from, const std::string& newPublicKey,
                                    const std::string& signature) {
    json j = {
        {"type", "KEY_ROTATION"},
        {"from", from},
        {"new_public_key", newPublicKey},
        {"signature", signature}
    };
    return j.dump();
}

// ERROR: report an error
inline std::string buildError(const std::string& from, const std::string& message) {
    json j = {
        {"type", "ERROR"},
        {"from", from},
        {"message", message}
    };
    return j.dump();
}

// --- Message parser (parse incoming JSON string) ---

// --- Encrypted message wrapper ---

// Wrap any message in an encrypted envelope using session key K
inline std::string buildEncrypted(const std::string& from, const std::string& sessionKey,
                                  const std::string& innerMessage) {
    // innerMessage is the full JSON string of the original message
    // We import aesGcmEncrypt here via forward declaration
    json j = {
        {"type", "ENCRYPTED"},
        {"from", from},
        {"data", innerMessage}  // will be encrypted in sendEncrypted helper
    };
    return j.dump();
}

// --- Message parser ---

// Returns the parsed JSON object. Use j["type"] to determine message type,
// then access fields as needed.
inline json parseMessage(const std::string& rawMessage) {
    return json::parse(rawMessage);
}

#endif
