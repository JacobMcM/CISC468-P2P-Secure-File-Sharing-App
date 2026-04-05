"""
Test script for DH-EKE handshake with the C++ client (classical DHKE + PBKDF2).

This script acts as a peer and performs the full 4-message EKE exchange:
1. Send EKE_1: enc_w(α^a mod p) where w is derived via PBKDF2
2. Receive EKE_2: enc_w(α^b mod p) + enc_K(r_B)
3. Send EKE_3: enc_K(r_A || r_B || RSA_pub)
4. Receive EKE_4: enc_K(r_A || RSA_pub_peer)

Setup:
    1. Start the C++ client: ./p2pclient
    2. In the client, run: password
       Enter peer name: EKETest
       Enter shared password: testpassword123
    3. In another terminal: python3 tests/test_eke.py
"""

import socket
import struct
import json
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 5001
PASSWORD = "testpassword123"
MY_NAME = "EKETest"
PEER_NAME = "Cameron Mac"

# RFC 3526 Group 14 prime (2048-bit) -- must match C++ implementation
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

# Fake RSA public key PEM for testing
FAKE_RSA_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWe
FbXmrkMifMJkXAiMmBSwAGFAXzMVLMdSGJOF5kKLNEkTn3kDPHYaNNYFvhQZ1oD1
DDSuPhMBM2LzGLCIAbD5DpMCGGJPSXN1gNPYGYN9KfTHYGPMMKL2mONjLPOBVkMh
HAPaBDO0y1KmOZdDAzBl5OzpPFaxSlk7JlBIBq9HOjzCGJMEYJkJYFaVLwOF0FkE
KYNJXMaasDmGzYGONxjA2c0HbkHj3LGCPBEA2bL9JQBMGGMrzTILOim1bian7HMi
L0aDKIGmrMtJAP5m7dBRfNJR9QJNAwDlxnCMHEz3yCDvfkGMKQIRAe0x/m7IjaLJ
2QIDAQAB
-----END PUBLIC KEY-----"""

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

def derive_eke_key(password, name_a, name_b):
    """Derive AES key from password using PBKDF2-HMAC-SHA256 with deterministic salt."""
    names = sorted([name_a, name_b])
    combined = f"{names[0]}:{names[1]}"
    salt_hash = hashlib.sha256(combined.encode()).digest()
    salt = salt_hash[:16]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())

def aes_gcm_encrypt(key, plaintext):
    """Encrypt with AES-256-GCM, return base64(IV + ciphertext + tag)."""
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    combined = iv + ct_and_tag
    return base64.b64encode(combined).decode()

def aes_gcm_decrypt(key, b64data):
    """Decrypt AES-256-GCM from base64(IV + ciphertext + tag)."""
    combined = base64.b64decode(b64data)
    iv = combined[:12]
    ct_and_tag = combined[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct_and_tag, None)

def int_to_bytes_256(n):
    """Convert integer to 256-byte big-endian bytes (pad with leading zeros)."""
    raw = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    if len(raw) < 256:
        raw = b'\x00' * (256 - len(raw)) + raw
    return raw

def test_eke():
    print("=" * 50)
    print("DH-EKE HANDSHAKE TEST (Classical DHKE + PBKDF2)")
    print("=" * 50)

    # Step 1: Derive password key W
    W = derive_eke_key(PASSWORD, MY_NAME, PEER_NAME)
    print(f"Password key derived (PBKDF2-HMAC-SHA256, 600k iterations)")

    # Step 2: Generate classical DH key pair
    # Private exponent a ∈ {2, 3, ..., p-2}
    import secrets
    a = secrets.randbelow(P - 3) + 2  # random in [2, p-2]
    # Public value α^a mod p
    pub_a = pow(ALPHA, a, P)
    pub_a_bytes = int_to_bytes_256(pub_a)  # 256 bytes
    print(f"Generated DH key pair (private exponent: {a.bit_length()} bits)")

    # Step 3: Connect and send EKE_1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)  # PBKDF2 with 600k iterations can be slow
    sock.connect((HOST, PORT))
    print("Connected to peer")

    c1 = aes_gcm_encrypt(W, pub_a_bytes)
    eke1 = {"type": "EKE_1", "from": MY_NAME, "c1": c1}
    send_message(sock, json.dumps(eke1))
    print("Sent EKE_1 (encrypted DH public value)")

    # Step 4: Receive EKE_2
    response = receive_message(sock)
    if not response:
        print("No EKE_2 response!")
        sock.close()
        return False

    msg2 = json.loads(response)
    if msg2["type"] == "ERROR":
        print(f"Error: {msg2['message']}")
        sock.close()
        return False

    print(f"Received EKE_2 from {msg2['from']}")

    # Decrypt peer's DH public value
    peer_pub_bytes = aes_gcm_decrypt(W, msg2["c2"])
    peer_pub_b = int.from_bytes(peer_pub_bytes, byteorder='big')
    print(f"  Peer DH public value decrypted ({len(peer_pub_bytes)} bytes)")

    # Derive session key K = SHA-256(α^(ab) mod p)
    # Use unpadded bytes to match C++ BN_bn2bin behavior
    shared_secret = pow(peer_pub_b, a, P)
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    K = hashlib.sha256(shared_secret_bytes).digest()
    print(f"  Session key K derived")

    # Decrypt challenge r_B
    r_B = aes_gcm_decrypt(K, msg2["c3"])
    print(f"  Challenge r_B received ({len(r_B)} bytes)")

    # Step 5: Send EKE_3
    r_A = os.urandom(16)
    payload = r_A + r_B + FAKE_RSA_PEM.encode()
    c4 = aes_gcm_encrypt(K, payload)
    eke3 = {"type": "EKE_3", "from": MY_NAME, "c4": c4}
    send_message(sock, json.dumps(eke3))
    print("Sent EKE_3 (challenges + RSA public key)")

    # Step 6: Receive EKE_4
    response4 = receive_message(sock)
    if not response4:
        print("No EKE_4 response!")
        sock.close()
        return False

    msg4 = json.loads(response4)
    print(f"Received EKE_4 from {msg4['from']}")

    # Decrypt and verify
    plaintext4 = aes_gcm_decrypt(K, msg4["c5"])
    r_A_echo = plaintext4[:16]
    peer_rsa_pem = plaintext4[16:].decode()

    if r_A_echo == r_A:
        print("  Challenge r_A verified OK!")
    else:
        print("  Challenge r_A MISMATCH!")
        sock.close()
        return False

    if "BEGIN PUBLIC KEY" in peer_rsa_pem:
        lines = peer_rsa_pem.strip().split("\n")
        print(f"  Received peer RSA key ({len(lines)} lines)")
    else:
        print("  No RSA key in response!")
        sock.close()
        return False

    sock.close()
    print("\nDH-EKE HANDSHAKE TEST PASSED!")
    return True

if __name__ == "__main__":
    print(f"Make sure the C++ client is running and has set:")
    print(f"  password -> peer name: {MY_NAME}, password: {PASSWORD}")
    print()
    try:
        test_eke()
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
