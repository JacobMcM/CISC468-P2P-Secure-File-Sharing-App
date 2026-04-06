#include "filemanager.h"
#include "json.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

// OpenSSL for base64 encoding/decoding
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace fs = std::filesystem;

// --- Base64 helpers using OpenSSL ---

static std::string base64Encode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);

    BUF_MEM* bufPtr;
    BIO_get_mem_ptr(b64, &bufPtr);
    std::string encoded(bufPtr->data, bufPtr->length);

    BIO_free_all(b64);
    return encoded;
}

static std::string fmBase64Decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), input.size());
    b64 = BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::string output(input.size(), '\0');
    int len = BIO_read(b64, &output[0], input.size());
    if (len > 0) {
        output.resize(len);
    } else {
        output.clear();
    }

    BIO_free_all(b64);
    return output;
}

// --- File manager functions ---

static std::string s_baseDir;

void setBaseDir(const std::string& dir) {
    s_baseDir = dir;
}

std::string getSharedDir() {
    std::string dir = (s_baseDir.empty() ? std::string(getenv("HOME")) + "/.p2pclient" : s_baseDir) + "/shared";
    fs::create_directories(dir);
    return dir;
}

std::string getDownloadsDir() {
    std::string dir = (s_baseDir.empty() ? std::string(getenv("HOME")) + "/.p2pclient" : s_baseDir) + "/downloads";
    fs::create_directories(dir);
    return dir;
}

std::vector<FileInfo> getSharedFileList(const KeyPair& kp) {
    std::vector<FileInfo> files;
    std::string sharedDir = getSharedDir();

    for (const auto& entry : fs::directory_iterator(sharedDir)) {
        if (!entry.is_regular_file()) continue;

        // Read file contents for hashing
        std::ifstream f(entry.path(), std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
        f.close();

        FileInfo info;
        info.name = entry.path().filename().string();
        info.size = entry.file_size();
        info.hash = sha256Hash(contents);
        info.signature = rsaPssSign(kp, info.hash);
        files.push_back(info);
    }

    return files;
}

std::string readSharedFile(const std::string& filename) {
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename: " << filename << std::endl;
        return "";
    }

    std::string path = getSharedDir() + "/" + filename;
    if (!fs::exists(path)) {
        std::cerr << "File not found: " << filename << std::endl;
        return "";
    }

    std::ifstream file(path, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    file.close();
    return contents;
}

std::string readFileBase64(const std::string& filename) {
    std::string path = getSharedDir() + "/" + filename;

    // Prevent path traversal
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename: " << filename << std::endl;
        return "";
    }

    if (!fs::exists(path)) {
        std::cerr << "File not found: " << filename << std::endl;
        return "";
    }

    // Read file contents
    std::ifstream file(path, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    file.close();

    return base64Encode(contents);
}

bool saveFileFromBase64(const std::string& filename, const std::string& base64Data) {
    // Prevent path traversal
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename: " << filename << std::endl;
        return false;
    }

    std::string dir = getDownloadsDir();
    std::string path = dir + "/" + filename;

    std::string decoded = fmBase64Decode(base64Data);
    if (decoded.empty()) {
        std::cerr << "Failed to decode file data" << std::endl;
        return false;
    }

    std::ofstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to write file: " << path << std::endl;
        return false;
    }

    file.write(decoded.data(), decoded.size());
    file.close();

    std::cout << "File saved to " << path << std::endl;
    return true;
}

bool saveFileEncrypted(const std::string& filename, const std::string& contents,
                       const std::string& passphrase) {
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename: " << filename << std::endl;
        return false;
    }

    std::string encrypted = encryptForStorage(passphrase, contents);
    if (encrypted.empty()) {
        std::cerr << "Failed to encrypt file for storage" << std::endl;
        return false;
    }

    std::string dir = getDownloadsDir();
    std::string path = dir + "/" + filename + ".enc";

    std::ofstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to write file: " << path << std::endl;
        return false;
    }

    file.write(encrypted.data(), encrypted.size());
    file.close();

    std::cout << "File encrypted and saved to " << path << std::endl;
    return true;
}

std::string readFileDecrypted(const std::string& filename, const std::string& passphrase) {
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename: " << filename << std::endl;
        return "";
    }

    std::string dir = getDownloadsDir();
    std::string path = dir + "/" + filename + ".enc";

    if (!fs::exists(path)) {
        std::cerr << "Encrypted file not found: " << path << std::endl;
        return "";
    }

    std::ifstream file(path, std::ios::binary);
    std::string encrypted((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();

    std::string decrypted = decryptFromStorage(passphrase, encrypted);
    if (decrypted.empty()) {
        std::cerr << "Failed to decrypt file (wrong passphrase?)" << std::endl;
    }
    return decrypted;
}

void saveFileMeta(const std::string& filename, const std::string& owner,
                  const std::string& hash, const std::string& signature) {
    std::string dir = getDownloadsDir();
    std::string path = dir + "/" + filename + ".meta";

    nlohmann::json meta = {
        {"owner", owner},
        {"hash", hash},
        {"signature", signature}
    };

    std::ofstream file(path);
    file << meta.dump(2);
    file.close();
}

bool loadFileMeta(const std::string& filename, std::string& owner,
                  std::string& hash, std::string& signature) {
    std::string dir = getDownloadsDir();
    std::string path = dir + "/" + filename + ".meta";

    if (!fs::exists(path)) return false;

    std::ifstream file(path);
    nlohmann::json meta = nlohmann::json::parse(file);
    file.close();

    owner = meta["owner"].get<std::string>();
    hash = meta["hash"].get<std::string>();
    signature = meta["signature"].get<std::string>();
    return true;
}

bool hasDownloadedFile(const std::string& filename) {
    std::string dir = getDownloadsDir();
    return fs::exists(dir + "/" + filename + ".enc");
}

std::string readDownloadedFile(const std::string& filename, const std::string& passphrase) {
    return readFileDecrypted(filename, passphrase);
}
