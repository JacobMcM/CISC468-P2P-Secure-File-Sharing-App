# C++ Client

## Dependencies

- **OpenSSL 3** (libssl, libcrypto)
- **Bonjour SDK** (dns_sd.h) — included on macOS, must be installed on Windows

## macOS

### Install dependencies
```bash
brew install openssl@3
```

### Build and run
```bash
clang++ -o p2pclient src/main.cpp src/crypto.cpp src/network.cpp src/filemanager.cpp src/mdns.cpp \
  -std=c++17 \
  -I/opt/homebrew/opt/openssl@3/include \
  -L/opt/homebrew/opt/openssl@3/lib \
  -lssl -lcrypto
./p2pclient
```

## Windows

### Install dependencies
1. **OpenSSL 3** — download from https://slproweb.com/products/Win32OpenSSL.html
2. **Bonjour SDK** — download from https://developer.apple.com/bonjour/ (or install iTunes, which bundles it)

### Build and run
```bash
g++ -o p2pclient.exe src/main.cpp src/crypto.cpp src/network.cpp src/filemanager.cpp src/mdns.cpp ^
  -std=c++17 ^
  -lssl -lcrypto -ldnssd -lws2_32
./p2pclient.exe
```

## Usage

On startup the client will:
1. Ask for a **peer name** (e.g. Alice)
2. Ask for a **device passphrase** (used to encrypt files at rest)
3. Generate a **2048-bit RSA key pair** (if first run)
4. Start listening for peers via mDNS

### Commands
| Command | Description |
|---|---|
| `list` | Show discovered peers |
| `password` | Set a pre-shared password for a peer (for EKE) |
| `handshake` | Authenticate with a peer (EKE first time, STS after) |
| `files` | Request a peer's file list |
| `request` | Request a file from a peer |
| `consent` | Accept/reject a pending file request |
| `rotate` | Rotate RSA keys and notify peers |
| `quit` | Exit the program |

All peers must be on the **same local network** for mDNS discovery to work.
