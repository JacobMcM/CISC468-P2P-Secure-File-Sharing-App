#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/evp.h>

// Holds the local peer's RSA key pair
struct KeyPair {
    EVP_PKEY* pkey = nullptr; // OpenSSL key object (contains both private and public)
};

// Generate a new RSA 2048-bit key pair
KeyPair generateKeyPair();

// Export the public key as a PEM string (SubjectPublicKeyInfo format)
std::string exportPublicKeyPEM(const KeyPair& kp);

// Export the private key as a PEM string (PKCS#8 format, unencrypted)
std::string exportPrivateKeyPEM(const KeyPair& kp);

// Import a peer's public key from a PEM string
// Caller must free the returned pointer with EVP_PKEY_free()
EVP_PKEY* importPublicKeyPEM(const std::string& pem);

// Save key pair to disk (private_key.pem and public_key.pem in the given directory)
bool saveKeysToDisk(const KeyPair& kp, const std::string& directory);

// Load key pair from disk. Returns {nullptr} if files don't exist
KeyPair loadKeysFromDisk(const std::string& directory);

// Free the EVP_PKEY inside a KeyPair
void freeKeyPair(KeyPair& kp);

// Compute SHA-256 hash of data, returned as a hex string
std::string sha256Hash(const std::string& data);

// Sign data with RSA-PSS using SHA-256. Returns base64-encoded signature
std::string rsaPssSign(const KeyPair& kp, const std::string& data);

// Verify an RSA-PSS signature. Returns true if valid
bool rsaPssVerify(EVP_PKEY* publicKey, const std::string& data, const std::string& base64Signature);

// --- Classical Diffie-Hellman (RFC 3526 Group 14, 2048-bit) ---

#include <openssl/bn.h>
#include <openssl/dh.h>

// Holds a classical DH key pair (private exponent + public value)
struct DHKeyPair {
    BIGNUM* privKey = nullptr;  // private exponent a (random)
    BIGNUM* pubKey = nullptr;   // public value α^a mod p
};

// Generate an ephemeral classical DH key pair using RFC 3526 Group 14
DHKeyPair generateDHKeyPair();

// Export DH public key (α^a mod p) as a hex string
std::string exportDHPublicKey(const DHKeyPair& dh);

// Export DH public key as raw big-endian bytes (for EKE encryption)
std::string exportDHPublicKeyRaw(const DHKeyPair& dh);

// Decode a base64 string to its raw bytes
std::string base64Decode(const std::string& input);

// Derive a 32-byte AES-256 session key from our private exponent and peer's public key (hex)
std::string deriveSessionKey(const DHKeyPair& myDH, const std::string& peerDHPublicHex);

// Derive session key from raw big-endian peer DH public key bytes (for EKE)
std::string deriveSessionKeyFromRaw(const DHKeyPair& myDH, const std::string& peerDHPublicRaw);

// Free the DH key pair
void freeDHKeyPair(DHKeyPair& dh);

// --- AES-256-GCM ---

// Encrypt plaintext with AES-256-GCM. Returns base64(IV + ciphertext + tag)
// sessionKey must be 32 bytes
std::string aesGcmEncrypt(const std::string& sessionKey, const std::string& plaintext);

// Decrypt AES-256-GCM. Input is base64(IV + ciphertext + tag)
// Returns plaintext, or empty string on failure (e.g. tampered data)
std::string aesGcmDecrypt(const std::string& sessionKey, const std::string& base64Data);

// --- EKE / Challenges ---

// Generate a cryptographically random 16-byte challenge
std::string generateChallenge();

// Derive a 32-byte AES key from a password for EKE
// Uses PBKDF2-HMAC-SHA256 with a deterministic salt derived from both peer names
std::string deriveEKEKey(const std::string& password,
                         const std::string& peerA, const std::string& peerB);

// --- Secure Local Storage ---

// Derive a 32-byte AES-256 key from a passphrase using PBKDF2-HMAC-SHA256
std::string deriveKeyFromPassphrase(const std::string& passphrase, const std::string& salt);

// Generate a random 16-byte salt
std::string generateSalt();

// Encrypt file contents for storage at rest. Returns salt + encrypted data (raw bytes)
std::string encryptForStorage(const std::string& passphrase, const std::string& plaintext);

// Decrypt file contents from storage at rest. Input is salt + encrypted data
std::string decryptFromStorage(const std::string& passphrase, const std::string& cipherData);

#endif
