# models.py
from dataclasses import dataclass, field, asdict
import json
import base64
import util

# --- DH-EKE messages ---

# all encryted byte messages are first encrypted, then converted into b64
# This inverts that process + error checking
def getEncryptedProp(msg, prop: str, key):
    prop_b64 = msg.get(prop)
    if not prop_b64: raise Exception(prop + " is undefined")
    prop_bytes = util.b64ToBytes(prop_b64)
    return util.decryptAES(prop_bytes, key)

def buildEKE1(sender: str, c1_bytes: bytes):
    c1 = util.bytesToB64(c1_bytes)
    eke1 = { "type":"EKE_1", "from":sender,"c1":c1}
    return json.dumps(eke1)

def buildEKE2(sender: str, c2_bytes: bytes, c3_bytes: bytes):
    c2 = util.bytesToB64(c2_bytes)
    c3 = util.bytesToB64(c3_bytes)
    eke2 = { "type":"EKE_2", "from":sender,"c2":c2,"c3":c3}
    return json.dumps(eke2)

def buildEKE3(sender: str, c4_bytes: bytes):
    c4 = util.bytesToB64(c4_bytes)
    eke3 = { "type":"EKE_3", "from":sender,"c4":c4}
    return json.dumps(eke3)

def buildEKE4(sender: str, c5_bytes: bytes):
    c5 = util.bytesToB64(c5_bytes)
    eke4 = { "type":"EKE_4", "from":sender,"c5":c5}
    return json.dumps(eke4)

# --- STS messages ---

def buildSTS1(sender, dhPublicKey):
    sts1 = {"type":"STS_1", "from":sender,"dh_public_key":dhPublicKey}
    return json.dumps(sts1)

def buildSTS2(sender, dhPublicKey, encryptedSignature):
    sts2 = {"type":"STS_2", "from":sender,"dh_public_key":dhPublicKey, "encrypted_signature":encryptedSignature}
    return json.dumps(sts2)

def buildSTS3(sender, encryptedSignature):
    sts3 = {"type":"STS_3", "from":sender, "encrypted_signature":encryptedSignature}
    return json.dumps(sts3)

# --- FILE_LIST transfer ---
def buildFileListRequest(sender):
    listReq = {"type":"FILE_LIST_REQUEST", "from":sender}
    return json.dumps(listReq)

def buildFileListResponse(sender, files):
    listRes = {"type":"FILE_LIST_RESPONSE", "from":sender, "files":files}
    return json.dumps(listRes)


# --- FILE transfer ---

