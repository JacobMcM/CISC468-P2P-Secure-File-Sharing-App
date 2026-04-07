#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <algorithm>

namespace fs = std::filesystem;

KeyPair generateKeyPair() {
    // Create a context for RSA key generation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Failed to create key generation context" << std::endl;
        return {nullptr};
    }

    // Initialize and configure for 2048-bit RSA
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Failed to initialize key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {nullptr};
    }

    // Generate the key pair
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Failed to generate RSA key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {nullptr};
    }

    EVP_PKEY_CTX_free(ctx);
    return {pkey};
}

std::string exportPublicKeyPEM(const KeyPair& kp) {
    if (!kp.pkey) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    // Write public key in SubjectPublicKeyInfo format
    PEM_write_bio_PUBKEY(bio, kp.pkey);

    // Read the BIO contents into a string
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    return pem;
}

std::string exportPrivateKeyPEM(const KeyPair& kp) {
    if (!kp.pkey) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    // Write private key in PKCS#8 format (unencrypted)
    PEM_write_bio_PrivateKey(bio, kp.pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    return pem;
}

EVP_PKEY* importPublicKeyPEM(const std::string& data) {
    // 1) Try PEM (-----BEGIN PUBLIC KEY-----)
    BIO* bio = BIO_new_mem_buf(data.c_str(), data.size());
    if (bio) {
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (pkey) return pkey;
    }

    // 2) Try base64-encoded DER PKIX (Go client format)
    std::string der = base64Decode(data);
    if (!der.empty()) {
        const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, der.size());
        if (pkey) return pkey;
    }

    // 3) Try raw DER PKIX
    {
        const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, data.size());
        if (pkey) return pkey;
    }

    std::cerr << "Failed to parse public key (tried PEM, base64-DER, raw DER)" << std::endl;
    return nullptr;
}

bool saveKeysToDisk(const KeyPair& kp, const std::string& directory) {
    if (!kp.pkey) return false;

    // Create directory if it doesn't exist
    fs::create_directories(directory);

    // Save private key
    std::string privPath = directory + "/private_key.pem";
    std::ofstream privFile(privPath);
    if (!privFile) {
        std::cerr << "Failed to open " << privPath << " for writing" << std::endl;
        return false;
    }
    privFile << exportPrivateKeyPEM(kp);
    privFile.close();

    // Set private key to owner-only read/write (chmod 600)
    fs::permissions(privPath,
        fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace);

    // Save public key
    std::string pubPath = directory + "/public_key.pem";
    std::ofstream pubFile(pubPath);
    if (!pubFile) {
        std::cerr << "Failed to open " << pubPath << " for writing" << std::endl;
        return false;
    }
    pubFile << exportPublicKeyPEM(kp);
    pubFile.close();

    return true;
}

KeyPair loadKeysFromDisk(const std::string& directory) {
    std::string privPath = directory + "/private_key.pem";

    if (!fs::exists(privPath)) {
        return {nullptr};
    }

    // Read private key file
    std::ifstream file(privPath);
    if (!file) {
        std::cerr << "Failed to open " << privPath << std::endl;
        return {nullptr};
    }
    std::string pem((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();

    // Parse the private key (contains all info needed to derive the public key too)
    BIO* bio = BIO_new_mem_buf(pem.c_str(), pem.size());
    if (!bio) return {nullptr};

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "Failed to parse private key from " << privPath << std::endl;
        return {nullptr};
    }

    return {pkey};
}

void freeKeyPair(KeyPair& kp) {
    if (kp.pkey) {
        EVP_PKEY_free(kp.pkey);
        kp.pkey = nullptr;
    }
}

// --- Base64 helpers for signatures ---

static std::string base64Encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM* bufPtr;
    BIO_get_mem_ptr(b64, &bufPtr);
    std::string encoded(bufPtr->data, bufPtr->length);
    BIO_free_all(b64);
    return encoded;
}

std::string base64Decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), input.size());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::string output(input.size(), '\0');
    int len = BIO_read(b64, &output[0], input.size());
    if (len > 0) output.resize(len);
    else output.clear();

    BIO_free_all(b64);
    return output;
}

// --- Hashing and Signing ---

std::string sha256Hash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

    // Convert to hex string
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    return oss.str();
}

std::string rsaPssSign(const KeyPair& kp, const std::string& data) {
    if (!kp.pkey) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    // Initialize signing with RSA-PSS and SHA-256
    EVP_PKEY_CTX* pkeyCtx = nullptr;
    if (EVP_DigestSignInit(ctx, &pkeyCtx, EVP_sha256(), nullptr, kp.pkey) <= 0) {
        std::cerr << "Failed to init signing" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    // Set RSA-PSS padding
    EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST);

    // Sign the data
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    // Get signature length
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    // Get the signature
    std::vector<unsigned char> sig(sigLen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) <= 0) {
        std::cerr << "Failed to sign data" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    return base64Encode(sig.data(), sigLen);
}

bool rsaPssVerify(EVP_PKEY* publicKey, const std::string& data, const std::string& base64Signature) {
    if (!publicKey || base64Signature.empty()) return false;

    // Decode the base64 signature
    std::string sigBytes = base64Decode(base64Signature);
    if (sigBytes.empty()) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    // Initialize verification with RSA-PSS and SHA-256
    EVP_PKEY_CTX* pkeyCtx = nullptr;
    if (EVP_DigestVerifyInit(ctx, &pkeyCtx, EVP_sha256(), nullptr, publicKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST);

    // Verify
    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx,
        reinterpret_cast<const unsigned char*>(sigBytes.data()), sigBytes.size());

    EVP_MD_CTX_free(ctx);
    return result == 1;
}

// --- Classical Diffie-Hellman (RFC 3526 Group 14, 2048-bit) ---

// RFC 3526 Group 14 prime (2048-bit safe prime, α=2)
static const char* RFC3526_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

static BIGNUM* s_dhPrime = nullptr;
static BIGNUM* s_dhGenerator = nullptr;

static void initDHParams() {
    if (!s_dhPrime) {
        BN_hex2bn(&s_dhPrime, RFC3526_PRIME_HEX);
    }
    if (!s_dhGenerator) {
        s_dhGenerator = BN_new();
        BN_set_word(s_dhGenerator, 2); // α = 2
    }
}

DHKeyPair generateDHKeyPair() {
    initDHParams();

    // Generate random private exponent a ∈ {2, 3, ..., p-2}
    BIGNUM* privKey = BN_new();
    BIGNUM* pMinus2 = BN_dup(s_dhPrime);
    BN_sub_word(pMinus2, 2); // p - 2

    // Generate random in range [0, p-3], then add 2 to get [2, p-2]
    BN_rand_range(privKey, pMinus2);
    BN_add_word(privKey, 2);
    BN_free(pMinus2);

    // Compute public value: α^a mod p
    BIGNUM* pubKey = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(pubKey, s_dhGenerator, privKey, s_dhPrime, ctx);
    BN_CTX_free(ctx);

    return {privKey, pubKey};
}

std::string exportDHPublicKey(const DHKeyPair& dh) {
    if (!dh.pubKey) return "";
    char* hex = BN_bn2hex(dh.pubKey);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string exportDHPublicKeyRaw(const DHKeyPair& dh) {
    if (!dh.pubKey) return "";
    // Export as big-endian bytes, padded to 256 bytes (2048 bits)
    int numBytes = BN_num_bytes(dh.pubKey);
    std::string raw(256, '\0');
    // Pad with leading zeros
    int offset = 256 - numBytes;
    BN_bn2bin(dh.pubKey, reinterpret_cast<unsigned char*>(&raw[offset]));
    return raw;
}

// Helper: compute shared secret α^(ab) mod p from private key and peer's public BIGNUM
static std::string computeSharedSecret(const BIGNUM* privKey, const BIGNUM* peerPubKey) {
    initDHParams();

    // K = peerPub^myPriv mod p = α^(ab) mod p
    BIGNUM* sharedSecret = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(sharedSecret, peerPubKey, privKey, s_dhPrime, ctx);
    BN_CTX_free(ctx);

    // Convert to bytes and hash with SHA-256 to get 32-byte AES key
    int numBytes = BN_num_bytes(sharedSecret);
    std::vector<unsigned char> secretBytes(numBytes);
    BN_bn2bin(sharedSecret, secretBytes.data());
    BN_free(sharedSecret);

    unsigned char aesKey[SHA256_DIGEST_LENGTH];
    SHA256(secretBytes.data(), numBytes, aesKey);
    return std::string(reinterpret_cast<char*>(aesKey), SHA256_DIGEST_LENGTH);
}

std::string deriveSessionKey(const DHKeyPair& myDH, const std::string& peerDHPublicHex) {
    if (!myDH.privKey) return "";

    BIGNUM* peerPub = nullptr;
    BN_hex2bn(&peerPub, peerDHPublicHex.c_str());
    if (!peerPub) {
        std::cerr << "Failed to parse peer DH public key" << std::endl;
        return "";
    }

    std::string result = computeSharedSecret(myDH.privKey, peerPub);
    BN_free(peerPub);
    return result;
}

std::string deriveSessionKeyFromRaw(const DHKeyPair& myDH, const std::string& peerDHPublicRaw) {
    if (!myDH.privKey || peerDHPublicRaw.empty()) return "";

    BIGNUM* peerPub = BN_bin2bn(
        reinterpret_cast<const unsigned char*>(peerDHPublicRaw.data()),
        peerDHPublicRaw.size(), nullptr);
    if (!peerPub) return "";

    std::string result = computeSharedSecret(myDH.privKey, peerPub);
    BN_free(peerPub);
    return result;
}

void freeDHKeyPair(DHKeyPair& dh) {
    if (dh.privKey) {
        BN_free(dh.privKey);
        dh.privKey = nullptr;
    }
    if (dh.pubKey) {
        BN_free(dh.pubKey);
        dh.pubKey = nullptr;
    }
}

// --- AES-256-GCM ---

static const int AES_GCM_IV_SIZE = 12;
static const int AES_GCM_TAG_SIZE = 16;

std::string aesGcmEncrypt(const std::string& sessionKey, const std::string& plaintext) {
    if (sessionKey.size() != 32) {
        std::cerr << "Invalid session key size" << std::endl;
        return "";
    }

    // Generate random 12-byte IV
    unsigned char iv[AES_GCM_IV_SIZE];
    RAND_bytes(iv, AES_GCM_IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Set IV
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr,
        reinterpret_cast<const unsigned char*>(sessionKey.data()), iv);

    // Encrypt
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_GCM_TAG_SIZE);
    int outLen = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    int totalLen = outLen;

    int finalLen = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &finalLen);
    totalLen += finalLen;

    // Get auth tag
    unsigned char tag[AES_GCM_TAG_SIZE];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);

    // Combine: IV (12) + ciphertext + tag (16)
    std::string combined;
    combined.append(reinterpret_cast<char*>(iv), AES_GCM_IV_SIZE);
    combined.append(reinterpret_cast<char*>(ciphertext.data()), totalLen);
    combined.append(reinterpret_cast<char*>(tag), AES_GCM_TAG_SIZE);

    return base64Encode(reinterpret_cast<const unsigned char*>(combined.data()), combined.size());
}

std::string aesGcmDecrypt(const std::string& sessionKey, const std::string& base64Data) {
    if (sessionKey.size() != 32) {
        std::cerr << "Invalid session key size" << std::endl;
        return "";
    }

    std::string combined = base64Decode(base64Data);
    if (combined.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        std::cerr << "Encrypted data too short" << std::endl;
        return "";
    }

    // Split: IV (12) + ciphertext + tag (16)
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(combined.data());
    size_t ciphertextLen = combined.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(combined.data() + AES_GCM_IV_SIZE);
    const unsigned char* tag = reinterpret_cast<const unsigned char*>(combined.data() + AES_GCM_IV_SIZE + ciphertextLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr,
        reinterpret_cast<const unsigned char*>(sessionKey.data()), iv);

    // Decrypt
    std::vector<unsigned char> plaintext(ciphertextLen);
    int outLen = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, ciphertextLen);
    int totalLen = outLen;

    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, const_cast<unsigned char*>(tag));

    // Finalize and verify tag
    int finalLen = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        std::cerr << "AES-GCM decryption failed: data may have been tampered with" << std::endl;
        return "";
    }

    totalLen += finalLen;
    return std::string(reinterpret_cast<char*>(plaintext.data()), totalLen);
}

// --- EKE / Challenges ---

std::string generateChallenge() {
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    return std::string(reinterpret_cast<char*>(buf), 16);
}

std::string deriveKeyFromPassphrase(const std::string& passphrase, const std::string& salt) {
    // PBKDF2 with HMAC-SHA256, 600,000 iterations, 32-byte output
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
            passphrase.c_str(), passphrase.size(),
            reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
            600000,       // iteration count (OWASP recommended minimum)
            EVP_sha256(), // PRF = HMAC-SHA256
            32, key) != 1) {
        std::cerr << "PBKDF2 key derivation failed" << std::endl;
        return "";
    }

    return std::string(reinterpret_cast<char*>(key), 32);
}

std::string deriveEKEKey(const std::string& password,
                         const std::string& peerA, const std::string& peerB) {
    // Sort names so both peers produce the same salt
    std::string nameA = peerA, nameB = peerB;
    if (nameA > nameB) std::swap(nameA, nameB);

    // Deterministic salt from sorted peer names
    std::string combined = nameA + ":" + nameB;
    unsigned char saltHash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), saltHash);
    std::string salt(reinterpret_cast<char*>(saltHash), 16); // first 16 bytes

    return deriveKeyFromPassphrase(password, salt);
}

std::string generateSalt() {
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    return std::string(reinterpret_cast<char*>(buf), 16);
}

std::string encryptForStorage(const std::string& passphrase, const std::string& plaintext) {
    std::string salt = generateSalt();
    std::string key = deriveKeyFromPassphrase(passphrase, salt);
    if (key.empty()) return "";

    std::string encrypted = aesGcmEncrypt(key, plaintext);
    if (encrypted.empty()) return "";

    // Return salt (16 bytes) + encrypted data (base64)
    return salt + encrypted;
}

std::string decryptFromStorage(const std::string& passphrase, const std::string& cipherData) {
    if (cipherData.size() < 16) return "";

    std::string salt = cipherData.substr(0, 16);
    std::string encrypted = cipherData.substr(16);

    std::string key = deriveKeyFromPassphrase(passphrase, salt);
    if (key.empty()) return "";

    return aesGcmDecrypt(key, encrypted);
}
