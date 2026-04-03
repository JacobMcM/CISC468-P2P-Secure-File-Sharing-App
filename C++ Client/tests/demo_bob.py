"""
Bob's terminal for the Oscar demo.
Connects to port 5001 (Oscar's proxy), does EKE handshake, requests file.

Terminal 1: ./p2pclient "Alice" 5555  (password -> Bob / ab123)
Terminal 2: python3 tests/demo_oscar.py
Terminal 3: python3 tests/demo_bob.py
Then in Alice's terminal: consent -> y
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

# Connect through Oscar on 5001 (not directly to Alice on 5555)
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

GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def send_message(sock, message):
    data = message.encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)

def receive_message(sock):
    hdr = sock.recv(4)
    if len(hdr) < 4: return None
    length = struct.unpack("!I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk: return None
        data += chunk
    return data.decode("utf-8")

def derive_eke_key(password, name_a, name_b):
    names = sorted([name_a, name_b])
    salt = hashlib.sha256(f"{names[0]}:{names[1]}".encode()).digest()[:16]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    return kdf.derive(password.encode())

def aes_gcm_encrypt(key, plaintext):
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ct).decode()

def aes_gcm_decrypt(key, b64data):
    raw = base64.b64decode(b64data)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None)

def main():
    print(f"""
{BOLD}  ╔════════════════════════════════════════╗
  ║   BOB - Requesting file from Alice     ║
  ║   (connecting through Oscar on {PORT})  ║
  ╚════════════════════════════════════════╝{RESET}
""")

    # --- EKE HANDSHAKE ---
    print(f"  {GREEN}[BOB] Starting DH-EKE handshake with Alice...{RESET}")
    W = derive_eke_key(PASSWORD, MY_NAME, PEER_NAME)
    a = secrets.randbelow(P - 3) + 2
    pub_a = pow(ALPHA, a, P)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))

    # EKE_1
    c1 = aes_gcm_encrypt(W, pub_a.to_bytes(256, 'big'))
    send_message(sock, json.dumps({"type": "EKE_1", "from": MY_NAME, "c1": c1}))
    print(f"  {GREEN}[BOB] Sent EKE_1 (encrypted DH value){RESET}")

    # EKE_2
    resp2 = json.loads(receive_message(sock))
    peer_pub = int.from_bytes(aes_gcm_decrypt(W, resp2["c2"]), 'big')
    ss = pow(peer_pub, a, P)
    ss_bytes = ss.to_bytes((ss.bit_length() + 7) // 8, 'big')
    K = hashlib.sha256(ss_bytes).digest()
    r_B = aes_gcm_decrypt(K, resp2["c3"])
    print(f"  {GREEN}[BOB] Received EKE_2, derived session key K{RESET}")

    # EKE_3
    r_A = os.urandom(16)
    c4 = aes_gcm_encrypt(K, r_A + r_B + FAKE_RSA_PEM.encode())
    send_message(sock, json.dumps({"type": "EKE_3", "from": MY_NAME, "c4": c4}))
    print(f"  {GREEN}[BOB] Sent EKE_3 (challenges + RSA key){RESET}")

    # EKE_4
    resp4 = json.loads(receive_message(sock))
    pt4 = aes_gcm_decrypt(K, resp4["c5"])
    verified = pt4[:16] == r_A
    print(f"  {GREEN}[BOB] Received EKE_4, challenge verified: {verified}{RESET}")
    print(f"  {GREEN}[BOB] EKE handshake complete!{RESET}")
    sock.close()

    input(f"\n  Press Enter to request secret.txt from Alice...\n")

    # --- FILE REQUEST ---
    print(f"  {GREEN}[BOB] Requesting secret.txt from Alice...{RESET}")
    print(f"  {GREEN}[BOB] (Alice needs to type 'consent' then 'y'){RESET}")

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.settimeout(60)
    sock2.connect((HOST, PORT))
    send_message(sock2, json.dumps({"type": "FILE_REQUEST", "from": MY_NAME, "filename": "secret.txt"}))

    print(f"  {GREEN}[BOB] Waiting for Alice to accept...{RESET}")
    resp = json.loads(receive_message(sock2))
    sock2.close()

    if resp["type"] == "FILE_TRANSFER":
        encrypted_data = resp["data"]
        try:
            plaintext = aes_gcm_decrypt(K, encrypted_data)
            print(f"\n  {GREEN}{BOLD}[BOB] File received and decrypted:{RESET}")
            print(f"  {GREEN}{BOLD}[BOB] Contents: \"{plaintext.decode().strip()}\"{RESET}")
        except:
            print(f"\n  {GREEN}[BOB] File received (not encrypted with session key){RESET}")
    elif resp["type"] == "ERROR":
        print(f"  Error: {resp['message']}")
    else:
        print(f"  Unexpected: {resp['type']}")

    print()

if __name__ == "__main__":
    main()
