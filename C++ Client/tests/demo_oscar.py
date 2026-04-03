"""
3-terminal Oscar demo.

Terminal 1: Alice (real C++ client on port 5555)
Terminal 2: Oscar (this script -- proxy on port 5001, forwards to Alice 5555)
Terminal 3: Bob (Python script that connects through Oscar)

Oscar sees all traffic but it's all encrypted.
"""

import socket
import struct
import json
import threading
import sys

OSCAR_PORT = 5001
ALICE_HOST = "127.0.0.1"
ALICE_PORT = 5555

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def display(direction, raw_bytes):
    try:
        msg = json.loads(raw_bytes.decode("utf-8"))
        msg_type = msg.get("type", "?")

        print(f"\n{YELLOW}  [{direction}] type={msg_type}{RESET}")

        for key, value in msg.items():
            if key == "type":
                continue
            val_str = str(value)
            if key in ("from", "filename", "original_owner"):
                print(f"  {key}: {val_str}")
            elif key == "data":
                print(f"  {key}: {RED}{val_str[:80]}...{RESET}")
                print(f"  {RED}  ^^^ THIS IS THE FILE -- ENCRYPTED, CANNOT READ ^^^{RESET}")
            elif len(val_str) > 60:
                print(f"  {key}: {RED}{val_str[:80]}...{RESET}")
            else:
                print(f"  {key}: {val_str}")

    except:
        print(f"  {direction}: ({len(raw_bytes)} bytes of data)")

def proxy_connection(client_sock):
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        alice_sock.connect((ALICE_HOST, ALICE_PORT))
    except:
        print(f"  {RED}Cannot reach Alice on port {ALICE_PORT}{RESET}")
        client_sock.close()
        return

    def forward(src, dst, direction):
        try:
            while True:
                hdr = recv_exact(src, 4)
                if not hdr: break
                length = struct.unpack("!I", hdr)[0]
                body = recv_exact(src, length)
                if not body: break
                display(direction, body)
                dst.sendall(hdr + body)
        except:
            pass
        finally:
            try: src.close()
            except: pass
            try: dst.close()
            except: pass

    t1 = threading.Thread(target=forward, args=(client_sock, alice_sock, "Bob -> Alice"), daemon=True)
    t2 = threading.Thread(target=forward, args=(alice_sock, client_sock, "Alice -> Bob"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

if __name__ == "__main__":
    print(f"""
{BOLD}  ╔════════════════════════════════════════════╗
  ║   OSCAR - NETWORK EAVESDROPPER (port {OSCAR_PORT})  ║
  ║   Forwarding to Alice on port {ALICE_PORT}         ║
  ╚════════════════════════════════════════════╝{RESET}

  Waiting for connections...
""")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", OSCAR_PORT))
    server.listen(5)

    try:
        while True:
            client_sock, addr = server.accept()
            print(f"  {CYAN}--- Connection intercepted from {addr} ---{RESET}")
            threading.Thread(target=proxy_connection, args=(client_sock,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n  Oscar stopped.")
        server.close()
