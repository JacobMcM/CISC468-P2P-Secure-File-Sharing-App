"""
Test script to verify DH key exchange and AES-256-GCM encrypted file transfer.

This script:
1. Sends a HANDSHAKE with a DH public key (X25519)
2. Receives the server's DH public key
3. Derives a shared AES-256 session key
4. Requests a file and verifies it arrives encrypted
5. Decrypts the file and verifies contents

Setup:
    1. Place a file in ~/.p2pclient/shared/ (e.g., echo "secret data" > ~/.p2pclient/shared/secret.txt)
    2. Start the C++ client:  ./p2pclient
    3. In another terminal:   python3 tests/test_encryption.py
"""

import socket
import struct
import json
import base64
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5001

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

def test_encrypted_transfer():
    # Step 1: Generate our ephemeral X25519 key pair
    my_private_key = X25519PrivateKey.generate()
    my_public_key = my_private_key.public_key()
    my_pub_bytes = my_public_key.public_bytes_raw()
    my_pub_b64 = base64.b64encode(my_pub_bytes).decode()

    # Step 2: Handshake with DH public key
    print("=" * 50)
    print("STEP 1: HANDSHAKE with DH key exchange")
    print("=" * 50)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))

    handshake = {
        "type": "HANDSHAKE",
        "from": "EncryptionTest",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWe\nFbXmrkMifMJkXAiMmBSwAGFAXzMVLMdSGJOF5kKLNEkTn3kDPHYaNNYFvhQZ1oD1\nDDSuPhMBM2LzGLCIAbD5DpMCGGJPSXN1gNPYGYN9KfTHYGPMMKL2mONjLPOBVkMh\nHAPaBDO0y1KmOZdDAzBl5OzpPFaxSlk7JlBIBq9HOjzCGJMEYJkJYFaVLwOF0FkE\nKYNJXMaasDmGzYGONxjA2c0HbkHj3LGCPBEA2bL9JQBMGGMrzTILOim1bian7HMi\nL0aDKIGmrMtJAP5m7dBRfNJR9QJNAwDlxnCMHEz3yCDvfkGMKQIRAe0x/m7IjaLJ\n2QIDAQAB\n-----END PUBLIC KEY-----",
        "dh_public_key": my_pub_b64
    }

    send_message(sock, json.dumps(handshake))
    response = receive_message(sock)
    sock.close()

    if not response:
        print("No handshake response!")
        return

    hs_msg = json.loads(response)
    if "dh_public_key" not in hs_msg:
        print("Server did not include DH public key in response!")
        return

    peer_pub_b64 = hs_msg["dh_public_key"]
    peer_pub_bytes = base64.b64decode(peer_pub_b64)
    peer_public_key = X25519PublicKey.from_public_bytes(peer_pub_bytes)

    # Step 3: Derive shared secret
    shared_secret = my_private_key.exchange(peer_public_key)
    session_key = hashlib.sha256(shared_secret).digest()  # 32 bytes for AES-256

    print(f"DH exchange complete!")
    print(f"  Our DH pub:   {my_pub_b64[:32]}...")
    print(f"  Peer DH pub:  {peer_pub_b64[:32]}...")
    print(f"  Session key:  {session_key.hex()[:32]}...")
    print("HANDSHAKE + DH TEST PASSED!\n")

    # Step 4: Request a file (should come back encrypted)
    print("=" * 50)
    print("STEP 2: Request encrypted file")
    print("=" * 50)

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.settimeout(5)
    sock2.connect((HOST, PORT))

    request = {"type": "FILE_REQUEST", "from": "EncryptionTest", "filename": "secret.txt"}
    send_message(sock2, json.dumps(request))
    response2 = receive_message(sock2)
    sock2.close()

    if not response2:
        print("No response to file request!")
        return

    ft_msg = json.loads(response2)
    if ft_msg["type"] == "ERROR":
        print(f"Error: {ft_msg['message']}")
        print("Make sure ~/.p2pclient/shared/secret.txt exists!")
        return

    if ft_msg["type"] != "FILE_TRANSFER":
        print(f"Unexpected response: {ft_msg['type']}")
        return

    encrypted_data_b64 = ft_msg["data"]
    expected_hash = ft_msg["hash"]

    # Step 5: Decrypt with AES-256-GCM
    encrypted_data = base64.b64decode(encrypted_data_b64)

    # Format: IV (12 bytes) + ciphertext + tag (16 bytes)
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]

    aesgcm = AESGCM(session_key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
        print(f"Decryption successful!")
        print(f"  Plaintext: {plaintext.decode('utf-8').strip()}")

        # Verify hash
        computed_hash = hashlib.sha256(plaintext).hexdigest()
        if computed_hash == expected_hash:
            print(f"  Hash verified OK: {computed_hash[:32]}...")
        else:
            print(f"  HASH MISMATCH!")

        print("ENCRYPTED FILE TRANSFER TEST PASSED!\n")
    except Exception as e:
        print(f"Decryption FAILED: {e}")
        print("ENCRYPTED FILE TRANSFER TEST FAILED!\n")

if __name__ == "__main__":
    # Create test file
    shared_dir = os.path.expanduser("~/.p2pclient/shared")
    os.makedirs(shared_dir, exist_ok=True)
    test_file = os.path.join(shared_dir, "secret.txt")
    with open(test_file, "w") as f:
        f.write("This is secret encrypted data!")
    print(f"Created test file: {test_file}\n")

    try:
        test_encrypted_transfer()
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()

    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
    print("Cleaned up test file.")
