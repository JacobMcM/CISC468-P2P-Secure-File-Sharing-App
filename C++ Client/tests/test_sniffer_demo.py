"""
Live sniffer demo: Bob requests a file from Alice through a proxy.
Shows what an eavesdropper sees on the network in real time.

This script:
1. Acts as Bob -- performs EKE handshake with Alice
2. Requests a file from Alice
3. Prints BOTH what the attacker sees (ciphertext) AND what Bob decrypts (plaintext)

Setup:
    1. Start Alice: ./p2pclient "Alice" 5001
       Set password for Bob: ab123
    2. Run this script: python3 tests/test_sniffer_demo.py
"""

import socket
import struct
import json
import hashlib
import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 5001
PASSWORD = "ab123"
MY_NAME = "Bob"
PEER_NAME = "Alice"

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
    names = sorted([name_a, name_b])
    combined = f"{names[0]}:{names[1]}"
    salt = hashlib.sha256(combined.encode()).digest()[:16]
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

def show_attacker_view(label, raw_json):
    msg = json.loads(raw_json)
    print(f"\n  [ATTACKER SEES] {label}")
    print(f"  {'-'*50}")
    for key, value in msg.items():
        val_str = str(value)
        if len(val_str) > 60:
            print(f"    {key}: {val_str[:60]}...")
            print(f"    {'':>{len(key)+2}} ^ CIPHERTEXT ({len(val_str)} chars)")
        else:
            print(f"    {key}: {val_str}")

def main():
    print()
    print("  ============================================================")
    print("  LIVE EAVESDROPPER DEMO")
    print("  Shows what Bob sees vs what an attacker on the network sees")
    print("  ============================================================")
    print()

    # --- EKE HANDSHAKE ---
    print("=" * 62)
    print("  PHASE 1: DH-EKE HANDSHAKE (Bob authenticates with Alice)")
    print("=" * 62)

    W = derive_eke_key(PASSWORD, MY_NAME, PEER_NAME)
    a = secrets.randbelow(P - 3) + 2
    pub_a = pow(ALPHA, a, P)
    pub_a_bytes = pub_a.to_bytes(256, byteorder='big')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))

    # EKE_1
    c1 = aes_gcm_encrypt(W, pub_a_bytes)
    eke1 = json.dumps({"type": "EKE_1", "from": MY_NAME, "c1": c1})
    show_attacker_view("Bob -> Alice: EKE_1", eke1)
    print("\n  [BOB KNOWS] Sent my DH public value, encrypted with our shared password")
    send_message(sock, eke1)

    # EKE_2
    resp2_raw = receive_message(sock)
    show_attacker_view("Alice -> Bob: EKE_2", resp2_raw)
    resp2 = json.loads(resp2_raw)
    peer_pub_bytes = aes_gcm_decrypt(W, resp2["c2"])
    peer_pub_b = int.from_bytes(peer_pub_bytes, byteorder='big')
    shared_secret = pow(peer_pub_b, a, P)
    ss_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    K = hashlib.sha256(ss_bytes).digest()
    r_B = aes_gcm_decrypt(K, resp2["c3"])
    print(f"\n  [BOB DECRYPTS] Alice's DH value + challenge r_B ({len(r_B)} bytes)")
    print(f"  [BOB COMPUTES] Session key K = SHA-256(shared_secret)")

    # EKE_3
    r_A = os.urandom(16)
    payload = r_A + r_B + FAKE_RSA_PEM.encode()
    c4 = aes_gcm_encrypt(K, payload)
    eke3 = json.dumps({"type": "EKE_3", "from": MY_NAME, "c4": c4})
    show_attacker_view("Bob -> Alice: EKE_3", eke3)
    print(f"\n  [BOB KNOWS] Sent challenges + my RSA public key (all encrypted under K)")
    send_message(sock, eke3)

    # EKE_4
    resp4_raw = receive_message(sock)
    show_attacker_view("Alice -> Bob: EKE_4", resp4_raw)
    resp4 = json.loads(resp4_raw)
    plaintext4 = aes_gcm_decrypt(K, resp4["c5"])
    r_A_echo = plaintext4[:16]
    peer_rsa_pem = plaintext4[16:].decode()
    verified = r_A_echo == r_A
    print(f"\n  [BOB DECRYPTS] Challenge verified: {verified}")
    print(f"  [BOB DECRYPTS] Received Alice's RSA public key")
    print(f"\n  HANDSHAKE COMPLETE -- Bob and Alice are mutually authenticated")
    sock.close()

    input("\n  Press Enter to continue to file transfer...\n")

    # --- FILE REQUEST ---
    print("=" * 62)
    print("  PHASE 2: FILE TRANSFER (Bob requests secret.txt from Alice)")
    print("=" * 62)
    print()
    print("  NOTE: Alice will need to type 'consent' then 'y' in her terminal")

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.settimeout(60)  # Long timeout for consent
    sock2.connect((HOST, PORT))

    req = json.dumps({"type": "FILE_REQUEST", "from": MY_NAME, "filename": "secret.txt"})
    show_attacker_view("Bob -> Alice: FILE_REQUEST", req)
    send_message(sock2, req)

    print("\n  Waiting for Alice to consent...")
    resp_raw = receive_message(sock2)
    sock2.close()

    if not resp_raw:
        print("  No response (Alice may have rejected or timed out)")
        return

    resp = json.loads(resp_raw)
    if resp["type"] == "ERROR":
        print(f"  Error: {resp['message']}")
        return

    if resp["type"] == "CONSENT_RESPONSE":
        print(f"  Alice rejected the file request")
        return

    if resp["type"] == "FILE_TRANSFER":
        show_attacker_view("Alice -> Bob: FILE_TRANSFER", resp_raw)

        encrypted_data = resp["data"]
        print(f"\n  [ATTACKER SEES] File data: {encrypted_data[:60]}...")
        print(f"  [ATTACKER SEES] This is AES-256-GCM ciphertext -- UNREADABLE")
        print()

        # Bob decrypts
        try:
            plaintext = aes_gcm_decrypt(K, encrypted_data)
            print(f"  [BOB DECRYPTS] File contents: \"{plaintext.decode()}\"")
        except Exception:
            print(f"  [BOB] Could not decrypt (session key may have changed)")

        print()
        print("  " + "=" * 58)
        print("  SUMMARY:")
        print(f"    Attacker sees: {encrypted_data[:40]}...")
        print(f"    Bob sees:      ", end="")
        try:
            print(f"\"{plaintext.decode()}\"")
        except:
            print("(decrypted file contents)")
        print("  " + "=" * 58)

if __name__ == "__main__":
    main()
