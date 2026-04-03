"""
Test script to verify HANDSHAKE message exchange with the C++ client.
Sends a HANDSHAKE message to the C++ client on port 5001 and prints the response.

Usage:
    1. Start the C++ client:  ./p2pclient
    2. In another terminal:   python3 tests/test_handshake.py
"""

import socket
import struct
import json

HOST = "127.0.0.1"
PORT = 5001

# A fake RSA public key PEM for testing (not a real key, just valid format)
FAKE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWe
FbXmrkMifMJkXAiMmBSwAGFAXzMVLMdSGJOF5kKLNEkTn3kDPHYaNNYFvhQZ1oD1
DDSuPhMBM2LzGLCIAbD5DpMCGGJPSXN1gNPYGYN9KfTHYGPMMKL2mONjLPOBVkMh
HAPaBDO0y1KmOZdDAzBl5OzpPFaxSlk7JlBIBq9HOjzCGJMEYJkJYFaVLwOF0FkE
KYNJXMaasDmGzYGONxjA2c0HbkHj3LGCPBEA2bL9JQBMGGMrzTILOim1bian7HMi
L0aDKIGmrMtJAP5m7dBRfNJR9QJNAwDlxnCMHEz3yCDvfkGMKQIRAe0x/m7IjaLJ
2QIDAQAB
-----END PUBLIC KEY-----"""

def send_message(sock, message):
    """Send a length-prefixed message (matching the C++ protocol)."""
    data = message.encode("utf-8")
    length = struct.pack("!I", len(data))  # 4 bytes, big-endian uint32
    sock.sendall(length + data)

def receive_message(sock):
    """Receive a length-prefixed message."""
    # Read 4-byte length prefix
    length_data = sock.recv(4)
    if len(length_data) < 4:
        return None
    length = struct.unpack("!I", length_data)[0]

    # Read the message body
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk

    return data.decode("utf-8")

def test_handshake():
    print(f"Connecting to C++ client at {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect((HOST, PORT))
        print("Connected!\n")

        # Build HANDSHAKE message
        handshake = {
            "type": "HANDSHAKE",
            "from": "TestScript",
            "public_key": FAKE_PUBLIC_KEY
        }

        print("Sending HANDSHAKE:")
        print(f"  from: {handshake['from']}")
        print(f"  public_key: {handshake['public_key'][:50]}...")
        send_message(sock, json.dumps(handshake))

        # Wait for response
        print("\nWaiting for response...")
        response = receive_message(sock)

        if response:
            msg = json.loads(response)
            print(f"\nReceived {msg['type']} from {msg['from']}:")
            if "public_key" in msg:
                # Show first and last lines of the PEM key
                lines = msg["public_key"].strip().split("\n")
                print(f"  {lines[0]}")
                print(f"  ... ({len(lines) - 2} lines) ...")
                print(f"  {lines[-1]}")
            print("\nHANDSHAKE TEST PASSED!")
        else:
            print("No response received.")
            print("HANDSHAKE TEST FAILED!")

    except socket.timeout:
        print("Connection timed out.")
        print("HANDSHAKE TEST FAILED!")
    except ConnectionRefusedError:
        print("Connection refused. Is the C++ client running?")
    finally:
        sock.close()

if __name__ == "__main__":
    test_handshake()
