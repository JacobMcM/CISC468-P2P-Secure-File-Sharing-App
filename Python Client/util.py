from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import base64
import random

# --- AES Utility functions ---
def encryptAES(plaintext: bytes, key: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # 96-bit nonce — must be unique per message
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

# assumes a nonce of 12 bytes
def decryptAES(msg: bytes, key: bytes):
    aesgcm = AESGCM(key)
    nonce = msg[:12]
    ciphertext = msg[12]    
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- TCP utility functions ---
def TCP_Sender(client_sock, msg: bytes):
    client_sock.sendall(len(msg).to_bytes(4, byteorder='big'))
    client_sock.sendall(msg)

def TCP_Reciever(conn):
    raw_len = conn.recv(4)
    msg_len = int.from_bytes(raw_len, byteorder='big')
    data = b''
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before full message received")
        data += chunk
    
    return json.loads(data.decode('utf-8'))

# --- conversion between json friendly b64, and encryption friendly bytes --- 

def bytesToB64(msg:bytes) -> str:
    msg_str = base64.b64encode(msg).decode('utf-8')
    return msg_str

def b64ToBytes(msg_str: str) -> bytes:
    msg = base64.b64decode(msg_str.encode('utf-8'))
    return msg

# --- DH exchange ---
ALPHA = 2
RFC3526_PRIME_HEX = \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
prime = int(RFC3526_PRIME_HEX, 16)

def genDHKeyPair():
    priv_key = random.randint(2, prime - 1)
    pub_key = pow(ALPHA, priv_key, prime)
    return priv_key, pub_key

# --- PBKDF2-HMAC-SHA256 ---

def hash_password(password, fromUser, toUser, iterations=600000):
    if fromUser > toUser:
        fromUser, toUser = toUser, fromUser
    combined = fromUser + ":" + toUser
    salt_hash = hashlib.sha256(combined.encode("utf-8")).digest()
    salt = salt_hash[:16]  # first 16 bytes, matching Go
    print("salt:")
    print(salt)
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )