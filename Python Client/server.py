import socket
import threading
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, ZeroconfServiceTypes
import os
from dotenv import load_dotenv
import json
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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
    private_key: str

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
                    "" # private key
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
                    "" # private key
                    )
                active_peers[new_peer.name] = new_peer
                print(f"[NETWORK] Service {name} added, ip: {socket.inet_ntop(socket.AF_INET, info.addresses[0])}, port: {info.port}")


    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_p2p._tcp.local.", listener)

    while not KILL_THREADS:
        pass

    zeroconf.unregister_service(info)
    zeroconf.close()


def kill_threads():
    global KILL_THREADS
    KILL_THREADS = True


def get_peers():
    global KILL_THREADS, active_peers
    if KILL_THREADS:
        return {}
    return active_peers




