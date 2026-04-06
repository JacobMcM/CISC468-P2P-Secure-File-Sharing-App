# Known-members and their private key-pairs
#    shared pairwise passwords in .env (for now)
# connected-members, members from known-members currently connected

# known-filelist - init empty

import base64
import hashlib
import secrets
import os
import server
import models
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import json
import threading
import util
import storage

#def genFilelist():
# generate filelist (encoded JSON object in folder)
#       signature RSA-PSS
#       files:     
#         json{
#             {"name", f.name},
#             {"size", f.size},
#             {"hash", f.hash},
#             {"signature", f.signature}
#         };

#def getFileList(Who):
    # establish client
    # Create fileList request:
    #   json j = {
    #       {"type", "FILE_LIST_REQUEST"},
    #       {"from", from}
    #   };
   

    # contact user
    #   run establishConnection(Who, client) => false || K
    #   if ^ false, end connection
    #   
    #   send file list request, encripted with K
    #   await response
    #   check reponse is of valid filelistResponse format
    #   Parse response, updating known-filelist with files found here
    # end contact

#def getFile(Who (user), What (file from known-filelist)):
    # index known members and known-filelist to get the data
    
    # contact user
    #   run establishConnection(Who, client) => false || K
    #   if ^ false, end connection
    #   
    #   send file list request, encripted with K
    #   await response
    #   check reponse is of valid filelistResponse format
    #   Parse response, updating known-filelist with files found here
    # end contact


def start_client(target_host, target_port):
    print("start_client", target_host, target_port)
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("got_sock")
    try:
        client_sock.connect((target_host, target_port))
    except Exception as e:
        client_sock.close()        
        print(f"[CLIENT] Error: {e}")
        return None    
    print(f"[CLIENT] Connected to {target_host}:{target_port}")
    return client_sock


def connect(peer: server.peer):
    print("peer: ")
    print(peer)
    client_sock = start_client(peer.ip, peer.port)
    if client_sock == None: return 

    
    print("peer private key: " + peer.private_key)  

    if peer.private_key.trim == "" or peer.private_key == None:
        K = establishFirstConnection(peer, client_sock)

# Runs EKE Session establishment, confirms peer private_key, returns Session key K
def establishFirstConnection(peer: server.peer, client_sock):
    tempW = "JacobLiam"    
    passwordKey = hash_password(tempW, server.localName, peer.name)
    
    print("Pass hashed")
    util.bytesToB64(passwordKey)

    # RFC 3526 Group 14 prime (2048-bit safe prime, α=2)
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
    priv_key = random.randint(2, prime - 1)
    pub_key = pow(ALPHA, priv_key, prime)
    plaintext = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')

    print("plaintext generated")

    # --- Encrypt ---
    c1 = util.encryptAES(plaintext, passwordKey)

    eke1 = models.buildEKE1(server.localName, c1)    
    print("eke1: " + eke1)

    util.TCP_Sender(eke1.encode())

    eke2 = {}       
    eke2 = util.TCP_Reciever(client_sock)
    print(eke2)
    
    if eke2["type"] != "EKE_2": raise Exception("Expected EKE_2")
    if eke2["from"] != peer.name: raise Exception("Expected different EKE_2 sender")
    if not eke2["c2"]: raise Exception("C2 is undefined")
    if not eke2["c3"]: raise Exception("C3 is undefined")

    shared_key = util.decryptAES(eke2["c2"], passwordKey)

    shared_key_int = int.from_bytes(shared_key, byteorder='big')
    K_int = pow(shared_key_int, priv_key, prime)
    K = K_int.to_bytes((K_int.bit_length() + 7) // 8, byteorder='big')

    print("K:" + str(K_int))
    challenge_b = util.decryptAES(eke2["c3"], K)

    challenge_a = os.urandom(32)
    challenge_ab = challenge_a + challenge_b


    c4 = util.encryptAES(challenge_ab, K)

    eke3 = models.buildEKE3(server.localName, c4)    
    print("eke3: " + eke3)

    util.TCP_Sender(eke3.encode())

    eke4 = {}       
    eke4 = util.TCP_Reciever(client_sock)
    print(eke4)

    if eke2["type"] != "EKE_4": raise Exception("Expected EKE_4")
    if eke2["from"] != peer.name: raise Exception("Expected different EKE_4 sender")
    if not eke2["c5"]: raise Exception("C5 is undefined")

    recieved_challenge_a = util.decryptAES(eke2["c5"], K)
    if challenge_a != recieved_challenge_a: raise Exception("Key Establishment challenge failed")
   

    return K

#recieve TCP data
def reciever(client_sock):
    raw_len = client_sock.recv(4)
    msg_len = int.from_bytes(raw_len, byteorder='big')
    data = b''
    while len(data) < msg_len:
        chunk = client_sock.recv(msg_len - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before full message received")
        data += chunk
    
    return json.loads(data.decode('utf-8'))

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

# wrapper for the processes which can be performed
def runner():
    # establish connection to the network    
    # run server

    reciever = threading.Thread(target=server.start_server, daemon=True)
    mDNS = threading.Thread(target=server.advertise_Service, daemon=True)
    reciever.start()
    mDNS.start()

    while True:
        print("peers in network")
        for p in server.active_peers:
            print(server.active_peers[p])

        i = input("(r: refresh, x: exit, [peer name]: begin DHEKE w/ peer)")

        if i == "x" or i == "X":
            server.kill_threads()
            reciever.join()
            mDNS.join()
            print("Server threads killed :)")
            break
        elif i == "r" or i == "R":
            continue
        else:
            connect(server.active_peers[i])

        


    # if first-time
    #   create and store public/private key
    







    # Call genFilelist

    # create empty known-filelist

    # list all available options
    # list all known files
    # prompt user to action
    # if "request file list"
    #    Prompt for who
    #    Call getFileList(Who)
    #    add files to knownfilelist

    # if "request file"
    #    Prompt for who, and what
    #    Call getFile(Who (user), What (file from known-filelist))
    







    # prompt user for


if __name__ == "__main__":
    runner()
