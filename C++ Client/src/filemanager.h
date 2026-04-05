#ifndef FILEMANAGER_H
#define FILEMANAGER_H

#include "protocol.h"
#include "crypto.h"
#include <string>
#include <vector>

// Set the base directory for this client (called once from main)
void setBaseDir(const std::string& dir);

// Get the shared files directory path
std::string getSharedDir();

// Get the downloads directory path
std::string getDownloadsDir();

// Scan the shared directory and return a list of FileInfo with SHA-256 hashes
// and RSA-PSS signatures for each file
std::vector<FileInfo> getSharedFileList(const KeyPair& kp);

// Read a file's raw contents from the shared directory
// Returns empty string if file not found
std::string readSharedFile(const std::string& filename);

// Read a file from the shared directory and return its contents as a base64 string
// Returns empty string if file not found
std::string readFileBase64(const std::string& filename);

// Save a base64-encoded file to the downloads directory
// Returns true on success
bool saveFileFromBase64(const std::string& filename, const std::string& base64Data);

// Save file contents encrypted at rest (using device passphrase via PBKDF2 + AES-256-GCM)
bool saveFileEncrypted(const std::string& filename, const std::string& contents,
                       const std::string& passphrase);

// Read and decrypt a file from the downloads directory
std::string readFileDecrypted(const std::string& filename, const std::string& passphrase);

// Save metadata for a downloaded file (original owner, hash, signature)
void saveFileMeta(const std::string& filename, const std::string& owner,
                  const std::string& hash, const std::string& signature);

// Load metadata for a downloaded file. Returns false if not found.
bool loadFileMeta(const std::string& filename, std::string& owner,
                  std::string& hash, std::string& signature);

// Check if we have a downloaded file available to share
bool hasDownloadedFile(const std::string& filename);

// Read a downloaded file's decrypted contents (for forwarding to another peer)
std::string readDownloadedFile(const std::string& filename, const std::string& passphrase);

#endif
