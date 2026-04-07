import os
import server
import models
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

    peer_RSA_pub = storage.getPeerPubRSA(peer.name)

    if peer_RSA_pub is None or peer_RSA_pub is None == "":
        try:
            K = establishFirstConnection(peer, client_sock)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            client_sock.close()
            return
    else:
        try:
            K = establishNthConnection(peer, peer_RSA_pub, client_sock)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            client_sock.close()
            return
    
    print("Session Key Established with "+ peer.name)
    while True:
        print("Select action:")
        print("  (1) Request File List")
        print("  (2) Request File")
        print("  (3) Send File")
        print("  (x) Close Connection")        
        print("  (r) Refresh Options")
        i = input("  >")

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
    w = storage.getPeerPassword(peer.name)
    if not w: raise Exception("User not in network") 
    passwordKey = util.hash_password(w, server.localName, peer.name)
    
    print("Pass hashed")

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
    if eke2.get("type") != "EKE_2": raise Exception("Expected EKE_2")
    if eke2.get("from") != peer.name: raise Exception("Expected different EKE_2 sender")

    shared_key = models.getEncryptedProp(eke2, "c2", passwordKey)
    K = util.deriveK(shared_key, priv_key)

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

    if eke4.get("type") != "EKE_4": raise Exception("Expected EKE_4")
    if eke4.get("from")!= peer.name: raise Exception("Expected different EKE_4 sender")

    c5 = models.getEncryptedProp(eke4, "c5", K)    
    recieved_challenge_a = c5[:16]
    if challenge_a != recieved_challenge_a: raise Exception("Key Establishment challenge failed")
    
    peer_pub_RSA = c5[16:]
    storage.addPeerPubRSA(peer.name, peer_pub_RSA)

    return K

def establishNthConnection(peer: server.peer, peer_RSA_pub: bytes, client_sock):
    # Generate DH key pair
    priv_key, pub_key = util.genDHKeyPair()
    pub_key_bytes = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')

    # build & send sts1
    sts1 = models.buildSTS1(server.localName, pub_key_bytes)    
    print("sts1: " + sts1)
    util.TCP_Sender(client_sock, sts1.encode())

    # await and recieve sts2
    sts2 = {}
    sts2 = util.TCP_Reciever(client_sock)
    print(sts2)
    if sts2.get("type") != "STS_2": raise Exception("Expected STS_2")
    if sts2.get("from") != peer.name: raise Exception("Expected different STS_2 sender")
    
    # extract shared peer dh_public_key
    shared_key = sts2.get("dh_public_key")
    if shared_key == None: raise Exception("DH Public Key is undefined")
    shared_key_bytes = util.b64ToBytes(shared_key)
    
    # establish shared key K
    K = util.deriveK(shared_key_bytes, priv_key)

    # build signed message we expect to recieve
    peer_message = shared_key_bytes + pub_key_bytes

    # extract peer signature
    peer_signature = models.getEncryptedProp(sts2, "encrypted_signature", K)

    # verify signature - Throws error on failure
    util.verifySign(peer_RSA_pub, peer_signature, peer_message)

    # build message we will sign
    our_message = pub_key_bytes + shared_key_bytes
    
    # build and encryt our signature
    our_RSA_priv = storage.getPrivRSA()
    our_signature = util.makeSign(our_RSA_priv, our_message)    
    encrypted_signature = util.encryptAES(our_signature, K)
    
    # build & send sts3
    sts3 = models.buildSTS3(server.localName, encrypted_signature)  
    util.TCP_Sender(client_sock, sts3.encode())

    return K


# wrapper for the processes which can be performed
def runner():
    # establish connection to the network    
    # run server

    reciever = threading.Thread(target=server.start_server, daemon=True)
    mDNS = threading.Thread(target=server.advertise_Service, daemon=True)
    reciever.start()
    mDNS.start()

    # Load RSA values
    storage.loadRSA()

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
