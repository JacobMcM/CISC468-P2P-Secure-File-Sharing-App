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
1. **OpenSSL 3** — installer from https://slproweb.com/products/Win32OpenSSL.html
   (use the full Win64 build, not "Light").
2. **Bonjour SDK for Windows** — https://developer.apple.com/bonjour/
   (or install iTunes, which bundles `dns_sd.dll`). Provides `dns_sd.h` and `dnssd.lib`.
3. **A C++ compiler** — easiest options:
   - **MSYS2 / MinGW-w64**: `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl`
   - **MSVC** via Visual Studio Build Tools.

### Build (MinGW, run from the `C++ Client/` directory)
```bat
g++ -o p2pclient.exe src/main.cpp src/crypto.cpp src/network.cpp src/filemanager.cpp src/mdns.cpp ^
  -std=c++17 ^
  -I"C:\Program Files\OpenSSL-Win64\include" ^
  -I"C:\Program Files\Bonjour SDK\Include" ^
  -L"C:\Program Files\OpenSSL-Win64\lib" ^
  -L"C:\Program Files\Bonjour SDK\Lib\x64" ^
  -lssl -lcrypto -ldnssd -lws2_32
```
Adjust the include/lib paths to wherever you installed OpenSSL and the Bonjour SDK.
With MSVC, compile with `cl` and link `libssl.lib libcrypto.lib dnssd.lib ws2_32.lib`.

### Runtime requirements
- The **Bonjour Service** must be running (`services.msc` → "Bonjour Service" → Start).
  Without it, mDNS discovery silently fails.
- `libssl-3-x64.dll` and `libcrypto-3-x64.dll` must be on your `PATH`
  (or copied next to `p2pclient.exe`).
- Allow `p2pclient.exe` through Windows Firewall on TCP **5001** and UDP **5353** (mDNS).

### Run
```bat
p2pclient.exe
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

## Running the tests

The test suite in `tests/` is written in Python and exercises the real
compiled C++ binary over TCP on `127.0.0.1:5001`. It covers:

- **Basic operation**: handshake (EKE + STS), file list, file pull, file push
- **Security checks**: hash verification, RSA-PSS signature verification,
  AES-256-GCM encryption-at-rest, EKE password authentication
- **Error scenarios**: wrong password, missing file, tampered file in
  transit, rejected consent, invalid/legacy message types, active
  man-in-the-middle attacker

### Prerequisites
1. Build the C++ client (see the macOS / Windows build sections above) so
   that the `p2pclient` binary exists in this folder.
2. Install the Python dependency used by the test scripts:
   ```bash
   pip install cryptography
   ```

### Mode 1: pull/security suite (`run_all_tests.py`)

This suite exercises file *pulls*, encryption, EKE, and the various
error paths. It needs the C++ client running in another terminal so that
the test peer can be registered before the tests connect.

1. **Terminal 1** — start the C++ client:
   ```bash
   cd "CISC468-P2P-Secure-File-Sharing-App/C++ Client"
   ./p2pclient
   ```
   At the prompts, enter:
   - peer name: `Cameron Mac`
   - device passphrase: anything (e.g. `devpass`)

   Then, at the client's `>` prompt, register the test peer's
   pre-shared password (used by EKE):
   ```
   password
   peer name: TestRunner
   password:  testpass123
   ```

2. **Terminal 2** — run the suite:
   ```bash
   cd "CISC468-P2P-Secure-File-Sharing-App/C++ Client"
   python3 tests/run_all_tests.py
   ```

You can also run individual files directly:
`test_handshake.py`, `test_encryption.py`, `test_file_sharing.py`,
`test_eke.py`, `test_attacker.py`, `test_oscar.py`.

### Mode 2: unattended push test (`test_push.py`)

This test exercises the **inbound push + consent** path (requirement 3).
It is fully unattended: it launches its own copy of `./p2pclient` as a
subprocess, feeds the device passphrase on stdin, sends a
`CONSENT_REQUEST` over the network, and automatically drives the
`consent` / `y` / `n` prompts on the client's stdin. No human input or
second terminal is required.

```bash
cd "CISC468-P2P-Secure-File-Sharing-App/C++ Client"
python3 tests/test_push.py
```

Expected output:
```
Launching C++ client subprocess...
--- push_test_accept.txt: expect ACCEPT ---
  PASS
--- push_test_reject.txt: expect REJECT ---
  PASS
All auto push tests PASSED
```

Make sure no other instance of `p2pclient` is already bound to TCP port
5001 when running this test, or the subprocess will fail to listen.
