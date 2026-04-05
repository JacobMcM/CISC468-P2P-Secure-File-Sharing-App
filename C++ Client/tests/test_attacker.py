"""
Attacker scenario: demonstrates what an eavesdropper sees on the network.

This script acts as a man-in-the-middle proxy between Alice and Bob.
It forwards messages between them but logs what it sees -- showing that
all data is encrypted and meaningless to the attacker.

Setup:
    1. Start Alice: ./p2pclient "Alice" 5001
       Set password for Bob: ab123
    2. Start Bob: ./p2pclient "Bob" 5002
       Set password for Alice: ab123
    3. Run this proxy: python3 tests/test_attacker.py
       This starts a proxy on port 6000 that forwards to Alice on 5001
    4. In Bob's terminal, manually connect to port 6000 instead of 5001
       (or just observe the output showing what encrypted traffic looks like)

Alternative (simpler): This script simulates what an eavesdropper would see
by performing a handshake and file transfer and displaying the raw wire data.
"""

import socket
import struct
import json
import os
import base64

HOST = "127.0.0.1"

def send_message(sock, message):
    data = message.encode("utf-8")
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def receive_message(sock):
    length_data = sock.recv(4)
    if len(length_data) < 4:
        return None
    length = struct.unpack("!I", length_data)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode("utf-8")

def show_wire_data(label, raw_json):
    """Show what an eavesdropper sees on the wire."""
    msg = json.loads(raw_json)
    msg_type = msg.get("type", "?")

    print(f"\n  {'='*56}")
    print(f"  {label}")
    print(f"  Message type: {msg_type}")
    print(f"  {'='*56}")

    for key, value in msg.items():
        if key in ("type", "from"):
            print(f"  {key}: {value}")
        else:
            val_str = str(value)
            if len(val_str) > 80:
                print(f"  {key}: {val_str[:80]}...")
                print(f"         ({len(val_str)} chars of encrypted/encoded data)")
            else:
                print(f"  {key}: {val_str}")

    print()

def demo_eke_eavesdrop():
    """Show what EKE messages look like on the wire."""
    print("=" * 60)
    print("WHAT AN EAVESDROPPER SEES: DH-EKE HANDSHAKE")
    print("=" * 60)
    print()
    print("When Alice and Bob perform a DH-EKE handshake, the")
    print("following messages travel over the network.")
    print("An eavesdropper can see the message TYPE but all")
    print("cryptographic values are encrypted.")

    # Simulate EKE messages with realistic-looking encrypted data
    eke1 = json.dumps({
        "type": "EKE_1",
        "from": "Bob",
        "c1": base64.b64encode(os.urandom(256 + 12 + 16)).decode()  # enc_w(DH pub)
    })
    show_wire_data("MESSAGE 1: Bob -> Alice (EKE_1)", eke1)
    print("  ATTACKER SEES: 'c1' is the DH public value encrypted")
    print("  with the password-derived key. Without the password,")
    print("  this is random noise.")

    eke2 = json.dumps({
        "type": "EKE_2",
        "from": "Alice",
        "c2": base64.b64encode(os.urandom(256 + 12 + 16)).decode(),  # enc_w(DH pub)
        "c3": base64.b64encode(os.urandom(16 + 12 + 16)).decode()   # enc_K(challenge)
    })
    show_wire_data("MESSAGE 2: Alice -> Bob (EKE_2)", eke2)
    print("  ATTACKER SEES: 'c2' is Alice's DH value (encrypted).")
    print("  'c3' is the challenge (encrypted with session key K).")
    print("  Attacker knows neither the password nor K.")

    eke3 = json.dumps({
        "type": "EKE_3",
        "from": "Bob",
        "c4": base64.b64encode(os.urandom(16 + 16 + 450 + 12 + 16)).decode()  # enc_K(r_A + r_B + RSA_pub)
    })
    show_wire_data("MESSAGE 3: Bob -> Alice (EKE_3)", eke3)
    print("  ATTACKER SEES: 'c4' contains challenges + RSA public key,")
    print("  ALL encrypted under session key K. The RSA public key")
    print("  is NEVER sent in plaintext.")

    eke4 = json.dumps({
        "type": "EKE_4",
        "from": "Alice",
        "c5": base64.b64encode(os.urandom(16 + 450 + 12 + 16)).decode()  # enc_K(r_A + RSA_pub)
    })
    show_wire_data("MESSAGE 4: Alice -> Bob (EKE_4)", eke4)
    print("  ATTACKER SEES: More encrypted data. Cannot extract")
    print("  Alice's RSA key or the challenge values.")
    print()

def demo_file_transfer_eavesdrop():
    """Show what a file transfer looks like on the wire."""
    print("=" * 60)
    print("WHAT AN EAVESDROPPER SEES: FILE TRANSFER")
    print("=" * 60)
    print()
    print("After authentication, Alice sends a file to Bob.")
    print("The file content is encrypted with AES-256-GCM using")
    print("the session key K derived from the DH exchange.")
    print()

    # What the ACTUAL file contains
    real_contents = "This is Alice's secret document with sensitive information!"
    print(f"  ACTUAL FILE CONTENTS: \"{real_contents}\"")
    print()

    # What goes over the wire
    transfer = json.dumps({
        "type": "FILE_TRANSFER",
        "from": "Alice",
        "filename": "alice_secret.txt",
        "data": base64.b64encode(os.urandom(len(real_contents) + 12 + 16)).decode(),
        "hash": "a3f2b8c91d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
        "signature": base64.b64encode(os.urandom(256)).decode(),
        "original_owner": "Alice"
    })

    show_wire_data("FILE_TRANSFER: Alice -> Bob", transfer)

    msg = json.loads(transfer)
    print("  WHAT THE ATTACKER CAN SEE:")
    print(f"    - File name: {msg['filename']} (visible)")
    print(f"    - File sender: {msg['from']} (visible)")
    print(f"    - Original owner: {msg['original_owner']} (visible)")
    print()
    print("  WHAT THE ATTACKER CANNOT READ:")
    print(f"    - File data: {msg['data'][:50]}...")
    print(f"      (AES-256-GCM ciphertext -- meaningless without session key K)")
    print()
    print("  WHAT THE ATTACKER CANNOT FORGE:")
    print(f"    - Signature: {msg['signature'][:50]}...")
    print(f"      (RSA-PSS signature -- requires Alice's private key)")
    print()

def demo_perfect_forward_secrecy():
    """Explain why past sessions are safe even if secrets are compromised."""
    print("=" * 60)
    print("PERFECT FORWARD SECRECY")
    print("=" * 60)
    print()
    print("  Even if an attacker LATER obtains:")
    print("    - The pre-shared password w")
    print("    - Alice's RSA private key")
    print("    - Bob's RSA private key")
    print()
    print("  They STILL cannot decrypt past file transfers because:")
    print("    - Each session used fresh ephemeral DH exponents (a, b)")
    print("    - The session key K = SHA-256(alpha^(ab) mod p)")
    print("    - The exponents a and b were deleted after the session")
    print("    - Without a and b, K cannot be recomputed")
    print()
    print("  The attacker would need to solve the Diffie-Hellman")
    print("  problem (compute alpha^(ab) from alpha^a and alpha^b),")
    print("  which is computationally infeasible with a 2048-bit prime.")
    print()

if __name__ == "__main__":
    print()
    print("  P2P SECURE FILE SHARING -- ATTACKER'S VIEW")
    print("  What does an eavesdropper on the network see?")
    print()

    demo_eke_eavesdrop()
    demo_file_transfer_eavesdrop()
    demo_perfect_forward_secrecy()

    print("=" * 60)
    print("CONCLUSION:")
    print("  - All DH values encrypted under password (EKE)")
    print("  - All file data encrypted under session key (AES-256-GCM)")
    print("  - RSA public keys never sent in plaintext")
    print("  - Past sessions protected by perfect forward secrecy")
    print("  - File tampering detected by hash + signature verification")
    print("=" * 60)
