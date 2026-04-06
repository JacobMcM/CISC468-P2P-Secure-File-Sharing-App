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

    peer_RSA_pub = storage.passwords.get('key')

    if peer_RSA_pub is None or peer_RSA_pub is None == "":
        try:
            K = establishFirstConnection(peer, client_sock)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            client_sock.close()
            return
    else:
        K = "TODO"
        #TODO STS key establishment
    
    print("Session Key Established with "+ peer.name)
    while True:
        print("Select action: (x to close connection, r to refresh options)")
        print("1. Request File List")
        print("2. Request File")
        print("3. Send File")
        i = input(">")

        if i == "x" or i == "X":
            print("Closing Connection...")
            client_sock.close()
            break
        elif i == "1" or i == 1:
            print("requesting File List")
            # TODO Request file list
        elif i == "2" or i == 2:
            print("requesting File")
            # TODO Request file
        elif i == "3" or i == 3:
            print("sending File")
            # TODO Request file
        else:
            continue # refresh




# Runs EKE Session establishment, confirms peer private_key, returns Session key K
def establishFirstConnection(peer: server.peer, client_sock):
    tempW = "JacobLiam"    
    passwordKey = util.hash_password(tempW, server.localName, peer.name)
    
    print("Pass hashed")
    util.bytesToB64(passwordKey)

    priv_key, pub_key = util.genDHKeyPair()
    pub_key_bytes = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')

    print("plaintext generated")

    # --- Encrypt ---
    c1 = util.encryptAES(pub_key_bytes, passwordKey)

    eke1 = models.buildEKE1(server.localName, c1)    
    print("eke1: " + eke1)

    util.TCP_Sender(client_sock, eke1.encode())

    eke2 = {}       
    eke2 = util.TCP_Reciever(client_sock)
    print(eke2)
    if eke2["type"] != "EKE_2": raise Exception("Expected EKE_2")
    if eke2["from"] != peer.name: raise Exception("Expected different EKE_2 sender")

    shared_key = models.getEncryptedProp(eke2, "c2", passwordKey)

    shared_key_int = int.from_bytes(shared_key, byteorder='big')
    K_int = pow(shared_key_int, priv_key, util.prime)
    K = K_int.to_bytes((K_int.bit_length() + 7) // 8, byteorder='big')

    print("K:" + str(K_int))
    challenge_b = models.getEncryptedProp(eke2, "c3", K)

    challenge_a = os.urandom(16)
    pub_RSA = storage.getPubRSA()
    challenge_ab = challenge_a + challenge_b + pub_RSA

    c4 = util.encryptAES(challenge_ab, K)

    eke3 = models.buildEKE3(server.localName, c4)    
    print("eke3: " + eke3)

    util.TCP_Sender(client_sock, eke3.encode())

    eke4 = {}       
    eke4 = util.TCP_Reciever(client_sock)
    print(eke4)

    if eke4["type"] != "EKE_4": raise Exception("Expected EKE_4")
    if eke4["from"] != peer.name: raise Exception("Expected different EKE_4 sender")

    c5 = models.getEncryptedProp(eke4, "c5", K)    
    recieved_challenge_a = c5[:16]
    if challenge_a != recieved_challenge_a: raise Exception("Key Establishment challenge failed")
    
    peer_pub_RSA = c5[16:]
    storage.addPeerPubRSA(peer.name, peer_pub_RSA)  

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
