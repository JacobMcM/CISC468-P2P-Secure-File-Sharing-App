"""
Network sniffer / proxy: intercepts traffic between two peers.

This acts as a transparent proxy between Bob and Alice.
Bob connects to this proxy (port 6000), and the proxy forwards
everything to Alice (port 5001). All messages are logged,
showing what an eavesdropper on the network would see.

Setup:
    1. Start Alice: ./p2pclient "Alice" 5001
       (set password for Bob if needed)
    2. Start this sniffer: python3 tests/test_sniffer.py
       (listens on port 6000, forwards to Alice on 5001)
    3. Start Bob: ./p2pclient "Bob" 6000
       (Bob thinks he's connecting to Alice, but goes through the sniffer)
       (set password for Alice if needed)

    Then in Bob's terminal: handshake -> Alice, files -> Alice, request -> Alice, etc.
    The sniffer terminal shows all intercepted traffic.
"""

import socket
import struct
import json
import threading
import sys

LISTEN_PORT = 6000
ALICE_HOST = "127.0.0.1"
ALICE_PORT = 5001

def recv_exact(sock, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def display_message(direction, raw_bytes):
    """Display intercepted message in a readable format."""
    try:
        msg = json.loads(raw_bytes.decode("utf-8"))
        msg_type = msg.get("type", "UNKNOWN")

        print(f"\n  {'>'*3 if 'Bob' in direction else '<'*3} {direction}")
        print(f"  Type: {msg_type}")

        for key, value in msg.items():
            if key == "type":
                continue
            val_str = str(value)
            if len(val_str) > 70:
                # This is encrypted/encoded data -- show it's ciphertext
                print(f"  {key}: {val_str[:70]}...")
                print(f"  {'':>{len(key)+2}}^ ENCRYPTED ({len(val_str)} chars)")
            else:
                print(f"  {key}: {val_str}")

        # Highlight what attacker can and cannot see
        if msg_type in ("EKE_1", "EKE_2", "EKE_3", "EKE_4"):
            print(f"  [ATTACKER] All crypto values are ENCRYPTED -- cannot read DH keys or challenges")
        elif msg_type == "FILE_TRANSFER":
            print(f"  [ATTACKER] File data is AES-256-GCM CIPHERTEXT -- cannot read file contents")
        elif msg_type in ("STS_1", "STS_2", "STS_3"):
            print(f"  [ATTACKER] DH values visible, but signatures are encrypted under session key")
        elif msg_type == "FILE_LIST_RESPONSE":
            print(f"  [ATTACKER] Can see file names/sizes, but cannot forge signatures")

    except Exception as e:
        print(f"  {direction}: (binary data, {len(raw_bytes)} bytes)")

def proxy_connection(client_sock, client_addr):
    """Handle one proxied connection."""
    # Connect to Alice
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        alice_sock.connect((ALICE_HOST, ALICE_PORT))
    except ConnectionRefusedError:
        print(f"  Cannot connect to Alice at {ALICE_HOST}:{ALICE_PORT}")
        client_sock.close()
        return

    def forward(src, dst, direction):
        """Forward messages from src to dst, logging each one."""
        try:
            while True:
                # Read length prefix (4 bytes)
                length_data = recv_exact(src, 4)
                if not length_data:
                    break

                length = struct.unpack("!I", length_data)[0]

                # Read message body
                body = recv_exact(src, length)
                if not body:
                    break

                # Log what the attacker sees
                display_message(direction, body)

                # Forward to destination
                dst.sendall(length_data + body)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except:
                pass
            try:
                dst.close()
            except:
                pass

    # Forward in both directions
    t1 = threading.Thread(target=forward, args=(client_sock, alice_sock, "Bob -> Alice"))
    t2 = threading.Thread(target=forward, args=(alice_sock, client_sock, "Alice -> Bob"))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    t1.join()
    t2.join()

if __name__ == "__main__":
    print()
    print("  ============================================")
    print("  NETWORK SNIFFER / EAVESDROPPER PROXY")
    print("  ============================================")
    print(f"  Listening on port {LISTEN_PORT}")
    print(f"  Forwarding to Alice at {ALICE_HOST}:{ALICE_PORT}")
    print()
    print("  Start Bob with: ./p2pclient \"Bob\" {0}".format(LISTEN_PORT))
    print("  All traffic between Bob and Alice will be logged here.")
    print("  ============================================")
    print()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)

    print(f"  Sniffer ready. Waiting for connections...\n")

    try:
        while True:
            client_sock, client_addr = server.accept()
            print(f"  --- New connection from {client_addr} ---")
            t = threading.Thread(target=proxy_connection, args=(client_sock, client_addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n  Sniffer stopped.")
        server.close()
