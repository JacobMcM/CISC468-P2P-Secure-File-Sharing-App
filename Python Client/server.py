import socket
import threading
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, ZeroconfServiceTypes
import os
from dotenv import load_dotenv
import json
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import util
import models
import storage

KILL_THREADS = False

# Configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5000       # Port to listen on

fileFolder = '/FileFolder'

active_peers={}
localName="JacobPC"

@dataclass
class peer:
    name: str
    ip: str
    port: str

@dataclass
class file:
    name: str

@dataclass
class Request:
    action: str        # e.g. "GET_USER", "DELETE_ITEM"
    payload: dict      # action-specific data

@dataclass  
class Response:
    success: bool
    data: dict
    error: str | None = None

def serialize(obj) -> bytes:
    return json.dumps(obj.__dict__).encode()

def deserialize_request(raw: bytes) -> Request:
    d = json.loads(raw.decode())
    return Request(**d)

# -------------------------------
# Dns Part
# -------------------------------
def advertise_Service():
    global KILL_THREADS, active_peers
    load_dotenv()
    JACOBIP = os.getenv('JACOBIP')

    zeroconf = Zeroconf()

    info = ServiceInfo(
        "_p2p._tcp.local.",
        localName + "._p2p._tcp.local.",
        addresses=[socket.inet_aton(JACOBIP)], # < My local
        port=5000,
    )

    zeroconf.register_service(info)

    class MyListener(ServiceListener):
        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            if info:
                updated_peer = peer(
                    name.split(".")[0], #name
                    socket.inet_ntop(socket.AF_INET, info.addresses[0]), #IP
                    info.port, #port
                )
                active_peers[updated_peer.name] = updated_peer
                print(f"[NETWORK] Service {name} updated")

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            print(f"[NETWORK] Service {name} removed")
            active_peers.pop(name.split(",")[0])

        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            if info:
                new_peer = peer(
                    name.split(".")[0], #name
                    socket.inet_ntop(socket.AF_INET, info.addresses[0]), #IP
                    info.port, #port
                    )
                active_peers[new_peer.name] = new_peer
                print(f"[NETWORK] Service {name} added, ip: {socket.inet_ntop(socket.AF_INET, info.addresses[0])}, port: {info.port}")


    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_p2p._tcp.local.", listener)

    while not KILL_THREADS:
        pass

    zeroconf.unregister_service(info)
    zeroconf.close()

# -------------------------------
# Server Part
# -------------------------------
def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    server_sock.settimeout(5)  # 5 second timeout
    print(f"[SERVER] Listening on {HOST}:{PORT}\n")

    K: bytes | None = None

    
    while not KILL_THREADS:
        try:
            sock, addr = server_sock.accept()

            msg = util.TCP_Reciever(sock)
            msgType = msg.get('type')            

            if msgType == None or msgType == "":
                #TODO return error
                K = None
                sock.close()
            
            match msgType:
                case "EKE_1":
                    K = establishFirstConnection(msg,sock)
                case "STS_1":
                    K = establishNthConnection(msg,sock)
                case "FILE_LIST_REQUEST":
                    print(msgType)
                    #TODO process Key Rotation
                case "FILE_REQUEST":
                    print(msgType)
                    #TODO process Key Rotation
                case "CONSENT_REQUEST":
                    print(msgType)
                    #TODO process Key Rotation
                case "FILE_TRANSFER":
                    print(msgType)
                    #TODO process Key Rotation
                case "KEY_ROTATION":
                    print(msgType)
                    #TODO process Key Rotation
                case _:
                    print(msgType)
                    #TODO send error msg

            #data = conn.recv(1024)
            #request = deserialize_request(data)

            ##match request.action:
            ##    case "List":
            ##    case "connect":
            #print(f"[SERVER] Received from {addr}: {data.decode()}\n")             

            #conn.sendall(f"Echo: {data.decode()}".encode())
            #conn.close()
            #print(f"[SERVER] Connection closed: {addr}\n")
        except socket.timeout:
            if KILL_THREADS:
                break
        except:
            break
    server_sock.close()

def establishFirstConnection(eke1, sock):
    tempW = "JacobLiam"

    # establish pair-wise password derived from w key
    sender = eke1.get("from")
    if not sender: raise Exception("From is undefiend")
    passwordKey = util.hash_password(tempW, localName, sender)
    
    # Generate DH key pair
    priv_key, pub_key = util.genDHKeyPair()

    # establish shared key K
    shared_key = models.getEncryptedProp(eke1, "c1", passwordKey)
    K = util.deriveK(shared_key, priv_key)

    # encrypt public DH key as c2
    pub_key_bytes = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')
    c2 = util.encryptAES(pub_key_bytes, passwordKey)

    # encrypt challenge b
    challenge_b = os.urandom(16)
    c3 = util.encryptAES(challenge_b, K)

    # build & send eke2
    eke2 = models.buildEKE2(localName, c2, c3)
    util.TCP_Sender(sock, eke2.encode())

    # await and recieve eke3
    eke3 = {}       
    eke3 = util.TCP_Reciever(client_sock)
    print(eke3)
    if eke3["type"] != "EKE_3": raise Exception("Expected EKE_3")
    if eke3["from"] != sender: raise Exception("Expected different EKE_3 sender")

    # confirm key establishment via challenge
    challenge_ab = models.getEncryptedProp(eke3, "c4", K)
    challenge_a =  challenge_ab[:16]
    recieved_challenge_b = challenge_ab[16:32]
    if challenge_b != recieved_challenge_b: raise Exception("Key Establishment challenge failed")

    #
    peer_pub_RSA = challenge_ab[32:]
    storage.addPeerPubRSA(sender, peer_pub_RSA)


    # encrypt challenge a and public RSA
    pub_RSA = storage.getPubRSA()
    c5 = util.encryptAES(challenge_a + pub_RSA, K)

    # build & send eke5
    eke5 = models.buildEKE4(localName, c5)
    util.TCP_Sender(sock, eke5.encode())
        
    return K

def kill_threads():
    global KILL_THREADS
    KILL_THREADS = True


def get_peers():
    global KILL_THREADS, active_peers
    if KILL_THREADS:
        return {}
    return active_peers




