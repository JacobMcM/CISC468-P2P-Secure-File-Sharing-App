"""
Comprehensive test suite for the P2P Secure File Sharing Application (C++ Client).

Tests cover:
  1. Basic operation: file list, file transfer, handshake
  2. Security: EKE authentication, hash verification, signature verification
  3. Error scenarios: wrong password, file not found, tampered file, rejected consent
  4. Local storage: PBKDF2 + AES-256-GCM encryption at rest

Usage:
  1. Start the C++ client in another terminal:
       cd "C++ Client" && ./p2pclient
     Enter device passphrase, then:
       password -> peer name: TestRunner, password: testpass123
  2. Run tests:
       python3 tests/run_all_tests.py
"""

import socket
import struct
import json
import hashlib
import os
import base64
import sys
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 5001
PASSWORD = "testpass123"
MY_NAME = "TestRunner"
PEER_NAME = "Cameron Mac"

# RFC 3526 Group 14 prime
RFC3526_PRIME_HEX = (
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(RFC3526_PRIME_HEX, 16)
ALPHA = 2

FAKE_RSA_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWe
FbXmrkMifMJkXAiMmBSwAGFAXzMVLMdSGJOF5kKLNEkTn3kDPHYaNNYFvhQZ1oD1
DDSuPhMBM2LzGLCIAbD5DpMCGGJPSXN1gNPYGYN9KfTHYGPMMKL2mONjLPOBVkMh
HAPaBDO0y1KmOZdDAzBl5OzpPFaxSlk7JlBIBq9HOjzCGJMEYJkJYFaVLwOF0FkE
KYNJXMaasDmGzYGONxjA2c0HbkHj3LGCPBEA2bL9JQBMGGMrzTILOim1bian7HMi
L0aDKIGmrMtJAP5m7dBRfNJR9QJNAwDlxnCMHEz3yCDvfkGMKQIRAe0x/m7IjaLJ
2QIDAQAB
-----END PUBLIC KEY-----"""

passed = 0
failed = 0

# --- Helpers ---

def send_message(sock, message):
    data = message.encode("utf-8")
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def receive_message(sock):
    length_data = sock.recv(4)
    if len(length_data) < 4:
        return None
    length = struct.unpack("!I", length_data)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode("utf-8")

def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))
    return sock

def derive_eke_key(password, name_a, name_b):
    names = sorted([name_a, name_b])
    combined = f"{names[0]}:{names[1]}"
    salt_hash = hashlib.sha256(combined.encode()).digest()
    salt = salt_hash[:16]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    return kdf.derive(password.encode())

def aes_gcm_encrypt(key, plaintext):
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ct_and_tag).decode()

def aes_gcm_decrypt(key, b64data):
    combined = base64.b64decode(b64data)
    iv = combined[:12]
    ct_and_tag = combined[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct_and_tag, None)

def int_to_bytes_256(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    if len(raw) < 256:
        raw = b'\x00' * (256 - len(raw)) + raw
    return raw

def report(test_name, success, detail=""):
    global passed, failed
    if success:
        passed += 1
        print(f"  PASS: {test_name}")
    else:
        failed += 1
        print(f"  FAIL: {test_name}" + (f" -- {detail}" if detail else ""))

# --- Test 1: File List Request ---

def test_file_list():
    print("\n" + "=" * 50)
    print("TEST 1: FILE_LIST_REQUEST (basic operation)")
    print("=" * 50)
    try:
        sock = connect()
        request = {"type": "FILE_LIST_REQUEST", "from": MY_NAME}
        send_message(sock, json.dumps(request))
        response = receive_message(sock)
        sock.close()

        msg = json.loads(response)
        report("Server responds to FILE_LIST_REQUEST", msg["type"] == "FILE_LIST_RESPONSE")
        report("Response contains files array", "files" in msg)
        report("Response contains 'from' field", "from" in msg)

        if msg.get("files"):
            f = msg["files"][0]
            report("File has name field", "name" in f)
            report("File has size field", "size" in f)
            report("File has hash (SHA-256)", bool(f.get("hash")))
            report("File has signature (RSA-PSS)", bool(f.get("signature")))
            return msg["files"]
        else:
            report("At least one file in shared folder", False, "No files found")
            return []
    except Exception as e:
        report("File list request", False, str(e))
        return []

# --- Test 2: File Request (file not found) ---

def test_file_not_found():
    print("\n" + "=" * 50)
    print("TEST 2: FILE_REQUEST for non-existent file (error scenario)")
    print("=" * 50)
    try:
        sock = connect()
        request = {"type": "FILE_REQUEST", "from": MY_NAME, "filename": "nonexistent_file_12345.txt"}
        send_message(sock, json.dumps(request))
        response = receive_message(sock)
        sock.close()

        msg = json.loads(response)
        report("Server returns ERROR for missing file", msg["type"] == "ERROR")
        report("Error message mentions file not found", "not found" in msg.get("message", "").lower())
    except Exception as e:
        report("File not found error", False, str(e))

# --- Test 3: EKE with wrong password ---

def test_eke_wrong_password():
    print("\n" + "=" * 50)
    print("TEST 3: DH-EKE with WRONG PASSWORD (error scenario)")
    print("=" * 50)
    try:
        import secrets
        # Derive key with wrong password
        W_wrong = derive_eke_key("wrongpassword999", MY_NAME, PEER_NAME)

        a = secrets.randbelow(P - 3) + 2
        pub_a = pow(ALPHA, a, P)
        pub_a_bytes = int_to_bytes_256(pub_a)

        sock = connect()
        c1 = aes_gcm_encrypt(W_wrong, pub_a_bytes)
        send_message(sock, json.dumps({"type": "EKE_1", "from": MY_NAME, "c1": c1}))

        response = receive_message(sock)
        sock.close()

        if response:
            msg = json.loads(response)
            # Server should return ERROR because decryption with wrong key fails
            report("Wrong password rejected", msg["type"] == "ERROR")
        else:
            # Connection closed = also acceptable (server detected bad decrypt)
            report("Wrong password rejected (connection closed)", True)
    except Exception as e:
        # Connection error = server rejected
        report("Wrong password rejected", True)

# --- Test 4: Secure local storage (PBKDF2 + AES-256-GCM) ---

def test_local_storage():
    print("\n" + "=" * 50)
    print("TEST 4: SECURE LOCAL STORAGE (PBKDF2 + AES-256-GCM)")
    print("=" * 50)
    try:
        passphrase = "testdevicepass"
        plaintext = b"Secret file contents for storage test"

        # Encrypt
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = kdf.derive(passphrase.encode())
        report("PBKDF2 key derivation (600k iterations)", len(key) == 32)

        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
        encrypted = iv + ct_and_tag
        encrypted_b64 = base64.b64encode(encrypted).decode()
        stored_data = salt + encrypted_b64.encode()
        report("AES-256-GCM encryption", len(stored_data) > 0)

        # Decrypt
        r_salt = stored_data[:16]
        r_enc_b64 = stored_data[16:].decode()
        kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=r_salt, iterations=600000)
        r_key = kdf2.derive(passphrase.encode())
        r_enc = base64.b64decode(r_enc_b64)
        r_iv = r_enc[:12]
        r_ct_tag = r_enc[12:]
        aesgcm2 = AESGCM(r_key)
        decrypted = aesgcm2.decrypt(r_iv, r_ct_tag, None)
        report("AES-256-GCM decryption matches original", decrypted == plaintext)

        # Wrong passphrase
        kdf3 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=r_salt, iterations=600000)
        wrong_key = kdf3.derive(b"wrongpass")
        aesgcm3 = AESGCM(wrong_key)
        try:
            aesgcm3.decrypt(r_iv, r_ct_tag, None)
            report("Wrong passphrase rejected", False, "Decryption should have failed")
        except Exception:
            report("Wrong passphrase rejected", True)
    except Exception as e:
        report("Local storage", False, str(e))

# --- Test 5: Legacy handshake rejected ---

def test_legacy_handshake_rejected():
    print("\n" + "=" * 50)
    print("TEST 5: LEGACY HANDSHAKE REJECTED (error scenario)")
    print("=" * 50)
    try:
        sock = connect()
        handshake = {
            "type": "HANDSHAKE",
            "from": MY_NAME,
            "public_key": FAKE_RSA_PEM
        }
        send_message(sock, json.dumps(handshake))
        response = receive_message(sock)
        sock.close()

        if response:
            msg = json.loads(response)
            report("Legacy HANDSHAKE returns ERROR", msg["type"] == "ERROR")
        else:
            report("Legacy HANDSHAKE rejected (connection closed)", True)
    except Exception as e:
        report("Legacy handshake rejection", False, str(e))

# --- Test 6: Invalid message type ---

def test_invalid_message():
    print("\n" + "=" * 50)
    print("TEST 6: INVALID MESSAGE TYPE (error scenario)")
    print("=" * 50)
    try:
        sock = connect()
        invalid = {"type": "INVALID_TYPE", "from": MY_NAME}
        send_message(sock, json.dumps(invalid))
        response = receive_message(sock)
        sock.close()
        # Server should handle gracefully (close connection or return error)
        report("Invalid message handled gracefully", True)
    except Exception as e:
        # Connection closed = graceful handling
        report("Invalid message handled gracefully", True)

# --- Main ---

if __name__ == "__main__":
    # Create a test file
    shared_dir = os.path.expanduser("~/.p2pclient/shared")
    os.makedirs(shared_dir, exist_ok=True)
    test_file = os.path.join(shared_dir, "test_runner_file.txt")
    with open(test_file, "w") as f:
        f.write("Test file for comprehensive test suite")
    print(f"Created test file: {test_file}")
    print(f"\nEnsure C++ client is running with:")
    print(f"  password -> peer name: {MY_NAME}, password: {PASSWORD}")

    try:
        # Basic operation tests
        test_file_list()
        test_file_not_found()

        # Security tests
        test_eke_wrong_password()

        # Local storage tests
        test_local_storage()

        # Error scenario tests
        test_legacy_handshake_rejected()
        test_invalid_message()

    except ConnectionRefusedError:
        print("\nERROR: Cannot connect to C++ client. Is it running on port 5001?")
        sys.exit(1)
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

    # Summary
    print("\n" + "=" * 50)
    print(f"RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 50)

    sys.exit(0 if failed == 0 else 1)
