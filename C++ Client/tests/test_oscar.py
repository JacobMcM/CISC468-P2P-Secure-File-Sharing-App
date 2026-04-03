"""
Oscar's POV: passive eavesdropper watching Alice and Bob's file transfer.

This is a transparent proxy that sits between Alice and Bob.
It forwards all traffic unchanged but displays what Oscar sees.

Setup:
    1. Start Alice: ./p2pclient "Alice" 5001
       password -> Bob / ab123
    2. Start Oscar (this script): python3 tests/test_oscar.py
       (Oscar listens on port 5001, Alice must be on port 5555)

    ACTUALLY EASIER: Alice runs on 5555, Oscar proxies 5001 -> 5555.
    Bob connects to 5001 (thinks it's Alice, but Oscar is in the middle).

    Step by step:
    1. Start Alice on port 5555:  ./p2pclient "Alice" 5555
       password -> Bob / ab123
    2. Start Oscar: python3 tests/test_oscar.py
    3. Start Bob on port 5002:    ./p2pclient "Bob" 5002
       password -> Alice / ab123
    4. In Bob: handshake -> Alice (Bob sees Alice on port 5001 via mDNS...
       but actually we need Bob to connect to Oscar)

SIMPLEST APPROACH: Oscar just sniffs after the fact.
We do a normal Alice<->Bob transfer, then Oscar reads the .meta and .enc
files showing they're gibberish.

ACTUALLY: Let's use the proxy approach properly.
Alice on 5555. Oscar proxies 5001->5555. Bob on 5002 connects to "Alice" at 5001.
"""

import socket
import struct
import json
import threading
import sys
import textwrap

OSCAR_PORT = 5001      # Oscar listens here (pretending to be Alice)
ALICE_HOST = "127.0.0.1"
ALICE_PORT = 5555      # Real Alice

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def display_intercepted(direction, raw_bytes):
    try:
        msg = json.loads(raw_bytes.decode("utf-8"))
        msg_type = msg.get("type", "?")

        print(f"\n{YELLOW}{'='*60}{RESET}")
        print(f"{BOLD}  OSCAR INTERCEPTED: {direction}{RESET}")
        print(f"  Message type: {CYAN}{msg_type}{RESET}")

        for key, value in msg.items():
            if key == "type":
                continue
            val_str = str(value)
            if key == "from" or key == "filename" or key == "original_owner":
                print(f"  {key}: {val_str}")
            elif key == "data":
                print(f"  {key}: {RED}{val_str[:70]}...{RESET}")
                print(f"         {RED}^^^ FILE CONTENTS -- ENCRYPTED, OSCAR CANNOT READ{RESET}")
            elif len(val_str) > 60:
                print(f"  {key}: {RED}{val_str[:70]}...{RESET}")
                print(f"         {RED}^^^ ENCRYPTED ({len(val_str)} chars of ciphertext){RESET}")
            else:
                print(f"  {key}: {val_str}")

        if msg_type == "FILE_TRANSFER":
            print(f"\n  {RED}{BOLD}Oscar sees the file being sent but CANNOT read its contents.{RESET}")
            print(f"  {RED}The data field is AES-256-GCM ciphertext.{RESET}")
            print(f"  {RED}Without the session key K (from DH-EKE), it's random noise.{RESET}")
        elif msg_type in ("EKE_1", "EKE_2", "EKE_3", "EKE_4"):
            print(f"\n  {RED}Oscar sees the handshake but ALL values are encrypted.{RESET}")
            print(f"  {RED}Cannot extract DH keys, challenges, or RSA public keys.{RESET}")
        elif msg_type == "FILE_LIST_RESPONSE":
            files = msg.get("files", [])
            print(f"\n  {YELLOW}Oscar can see file names: {[f['name'] for f in files]}{RESET}")
            print(f"  {YELLOW}But cannot forge signatures or decrypt file contents.{RESET}")

    except Exception as e:
        print(f"  {direction}: (binary data, {len(raw_bytes)} bytes)")

def proxy_connection(client_sock, client_addr):
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        alice_sock.connect((ALICE_HOST, ALICE_PORT))
    except ConnectionRefusedError:
        print(f"\n  {RED}Cannot connect to Alice at {ALICE_HOST}:{ALICE_PORT}{RESET}")
        print(f"  Make sure Alice is running: ./p2pclient \"Alice\" {ALICE_PORT}")
        client_sock.close()
        return

    def forward(src, dst, direction):
        try:
            while True:
                length_data = recv_exact(src, 4)
                if not length_data:
                    break
                length = struct.unpack("!I", length_data)[0]
                body = recv_exact(src, length)
                if not body:
                    break
                display_intercepted(direction, body)
                dst.sendall(length_data + body)
        except Exception:
            pass
        finally:
            try: src.close()
            except: pass
            try: dst.close()
            except: pass

    t1 = threading.Thread(target=forward, args=(client_sock, alice_sock, "Bob --> Alice"), daemon=True)
    t2 = threading.Thread(target=forward, args=(alice_sock, client_sock, "Alice --> Bob"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

if __name__ == "__main__":
    print(f"""
{BOLD}  ╔══════════════════════════════════════════════════════╗
  ║         OSCAR - PASSIVE NETWORK EAVESDROPPER         ║
  ║                                                      ║
  ║  Oscar sits between Bob and Alice on the network.    ║
  ║  He can see all messages but cannot read encrypted    ║
  ║  contents without the session key or password.       ║
  ╚══════════════════════════════════════════════════════╝{RESET}

  Setup:
    Terminal 1: ./p2pclient "Alice" {ALICE_PORT}
                password -> Bob / ab123
    Terminal 2: python3 tests/test_oscar.py   (this script)
    Terminal 3: ./p2pclient "Bob" 5002
                password -> Alice / ab123
                handshake -> Alice
                request -> Alice -> secret.txt
                (Alice: consent -> y)

  Oscar proxies port {OSCAR_PORT} -> Alice on port {ALICE_PORT}
  Bob connects to {OSCAR_PORT} thinking it's Alice.
""")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", OSCAR_PORT))
    except OSError:
        print(f"  {RED}Port {OSCAR_PORT} is in use. Make sure no other client is on port {OSCAR_PORT}.{RESET}")
        sys.exit(1)
    server.listen(5)

    print(f"  {GREEN}Oscar listening on port {OSCAR_PORT}. Waiting for Bob...{RESET}\n")

    try:
        while True:
            client_sock, client_addr = server.accept()
            print(f"  {CYAN}--- Connection from {client_addr} ---{RESET}")
            t = threading.Thread(target=proxy_connection, args=(client_sock, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n  Oscar stopped.")
        server.close()
