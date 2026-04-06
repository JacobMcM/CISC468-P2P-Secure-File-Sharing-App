from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import base64

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

def TCP_Sender(client_sock, msg: bytes):
    client_sock.sendall(len(msg).to_bytes(4, byteorder='big'))
    client_sock.sendall(msg)

def TCP_Reciever(client_sock):
    raw_len = client_sock.recv(4)
    msg_len = int.from_bytes(raw_len, byteorder='big')
    data = b''
    while len(data) < msg_len:
        chunk = client_sock.recv(msg_len - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before full message received")
        data += chunk
    
    return json.loads(data.decode('utf-8'))

# used soley for testing
def bytesToB64(msg:bytes) -> str:
    msg_str = base64.b64encode(msg).decode('utf-8')
    return msg_str

def b64ToBytes(msg_str: str) -> bytes:
    msg = base64.b64decode(msg_str.encode('utf-8'))
    return msg