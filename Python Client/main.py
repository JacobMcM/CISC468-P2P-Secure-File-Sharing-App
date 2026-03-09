import socket
import threading
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, ZeroconfServiceTypes
import os
from dotenv import load_dotenv

KILL_THREADS = False
active_services = {}  # will hold name -> ServiceInfo

# Configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5000       # Port to listen on

# -------------------------------
# Dns Part
# -------------------------------
def advertise_Service():
    load_dotenv()
    JACOBIP = os.getenv('JACOBIP')

    zeroconf = Zeroconf()

    info = ServiceInfo(
        "_p2p._tcp.local.",
        "JacobPC._p2p._tcp.local.",
        addresses=[socket.inet_aton(JACOBIP)], # < My local
        port=5000,
    )
    zeroconf.register_service(info)

    class MyListener(ServiceListener):
        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            print(f"[NETWORK] Service {name} updated")

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            print(f"[NETWORK] Service {name} removed")
            active_services.pop(name,None)

        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            if info:
                active_services[name] = info
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

    try:
        while not KILL_THREADS:
            try:
                conn, addr = server_sock.accept()
                data = conn.recv(1024)
                print(f"[SERVER] Received from {addr}: {data.decode()}\n")
                conn.sendall(f"Echo: {data.decode()}".encode())
                conn.close()
                print(f"[SERVER] Connection closed: {addr}\n")
            except socket.timeout:
                if KILL_THREADS:
                    break
    finally:
        server_sock.close()
    

# -------------------------------
# Client Part
# -------------------------------
def start_client(target_host, target_port):
    print("start_client", target_host, target_port)
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("got_sock")
    client_sock.connect((target_host, target_port))
    print(f"[CLIENT] Connected to {target_host}:{target_port}")
    try:
        while True:
            msg = input("Message to send: ")
            if msg.lower() == 'exit':
                break
            client_sock.sendall(msg.encode())
            reply = client_sock.recv(1024)
            print(f"[CLIENT] Reply: {reply.decode()}")
    finally:
        client_sock.close()
        print("[CLIENT] Connection closed")

# -------------------------------
# Run Both
# -------------------------------
if __name__ == "__main__":
    # Run server in a background thread
    server = threading.Thread(target=start_server, daemon=True)
    mDNS = threading.Thread(target=advertise_Service, daemon=True)

    server.start()
    mDNS.start()

    while not KILL_THREADS:
        i = input("imput service name to contact, x to exit, i for info\n")

        if i == "x" or i == "X":
            KILL_THREADS = True
        elif i == "i" or i == "I":
            print(active_services)
        else:
            try:
                info = active_services[i]
                if not info:
                    break
                start_client(socket.inet_ntop(socket.AF_INET, info.addresses[0]),info.port)
            
            except:
                print("problem occured :/\n")

    server.join()
    mDNS.join()


