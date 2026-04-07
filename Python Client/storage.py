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
    # other values are [peername]:[peer_RSA_public], representing the public keys we know
    "Liam-PC": "JacobLiam",
    "Cam": "CamJacob",
    "Cam-test1": "CamJacob"
}

def getPeerPassword(name):
    global passwords
    # TODO decrypt this info
    return passwords.get(name)


RSA_PASS_PATH = "RSAPasswords.json"
RSAPasswords = {}

def loadRSA():
    global RSAPasswords
    if not os.path.exists(RSA_PASS_PATH):
        return
    with open(RSA_PASS_PATH) as f:
        RSAPasswords = json.load(f)

def saveRSA():
    global public_keys, fileList
    with open(RSA_PASS_PATH, "w") as f:
        json.dump(RSAPasswords, f, indent=4)

def getPubRSA():
    global RSAPasswords
    return util.b64ToBytes(RSAPasswords["RSA_Public"])

def getPrivRSA():
    global RSAPasswords
    return util.b64ToBytes(RSAPasswords["RSA_Private"])

def addPeerPubRSA(name, RSA_bytes):
    global RSAPasswords
    RSAPasswords[name] = util.bytesToB64(RSA_bytes)
    saveRSA()

def getPeerPubRSA(name):
    global RSAPasswords
    peerRSA = RSAPasswords.get(name)
    if peerRSA == None or peerRSA == "": return None
    return util.b64ToBytes(peerRSA)

def genRSA():
    global RSAPasswords
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
    RSAPasswords["RSA_Private"] = util.bytesToB64(private_bytes)
    RSAPasswords["RSA_Public"] = util.bytesToB64(public_bytes)
    saveRSA()


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

