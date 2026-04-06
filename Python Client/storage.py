# storage.py
import json, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import util

DATA_PATH = "network.json"

public_keys = {}
fileList = {}


PASS_PATH = "passwords.json"
passwords = {
    "General_access_HASH" : "", #TODO set before use, encode RSA_Private and files with pass matching hash
    "RSA_Private" : "",
    "RSA_Public" : "",
    # other values are [peername]:[peer_RSA_public], representing that the public keys we know
}

def loadPass():
    global passwords
    if not os.path.exists(PASS_PATH):
        return
    with open(PASS_PATH) as f:
        passwords = json.load(f)

def savePass():
    global public_keys, fileList
    with open(PASS_PATH, "w") as f:
        json.dump(passwords, f, indent=4)

def getPubRSA():
    return util.b64ToBytes(passwords["RSA_Public"])

def addPeerPubRSA(name, RSA_bytes):
    passwords[name] = util.bytesToB64(RSA_bytes)
    savePass()

def genRSA():
    global passwords
    # -- gen key ---
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # -- convert to bytes ---
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # TODO RSA private should be encrypted

    # --- save as converted b64 string
    passwords["RSA_Private"] = util.bytesToB64(private_bytes)
    passwords["RSA_Public"] = util.bytesToB64(public_bytes)
    savePass()


def load():
    global public_keys, fileList
    if not os.path.exists(DATA_PATH):
        return
    with open(DATA_PATH) as f:
        data = json.load(f)
        public_keys = data.get("public_keys", {})
        fileList = data.get("fileList", {})

def save():
    global public_keys, fileList
    with open(DATA_PATH, "w") as f:
        data = {
            "public_keys" : public_keys,
            "fileList" : fileList
        }
        json.dump(data, f, indent=4)

