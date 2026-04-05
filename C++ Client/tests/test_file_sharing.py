"""
Test script to verify file list and file transfer with the C++ client.

Setup:
    1. Place some files in ~/.p2pclient/shared/
    2. Start the C++ client:  ./p2pclient
    3. In another terminal:   python3 tests/test_file_sharing.py
"""

import socket
import struct
import json
import base64
import hashlib
import os

HOST = "127.0.0.1"
PORT = 5001

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

def test_file_list():
    print("=" * 50)
    print("TEST 1: FILE_LIST_REQUEST")
    print("=" * 50)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))

    request = {"type": "FILE_LIST_REQUEST", "from": "TestScript"}
    send_message(sock, json.dumps(request))

    response = receive_message(sock)
    sock.close()

    if response:
        msg = json.loads(response)
        if msg["type"] == "FILE_LIST_RESPONSE":
            files = msg["files"]
            print(f"Received file list from {msg['from']}:")
            if files:
                for f in files:
                    has_hash = "YES" if f.get("hash") else "no"
                    has_sig = "YES" if f.get("signature") else "no"
                    print(f"  - {f['name']} ({f['size']} bytes) [hash: {has_hash}, sig: {has_sig}]")
            else:
                print("  (no files shared)")
            print("FILE_LIST TEST PASSED!\n")
            return files
        else:
            print(f"Unexpected response: {msg['type']}")
            print("FILE_LIST TEST FAILED!\n")
    else:
        print("No response received")
        print("FILE_LIST TEST FAILED!\n")
    return []

def test_file_request(filename):
    print("=" * 50)
    print(f"TEST 2: FILE_REQUEST for '{filename}'")
    print("=" * 50)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))

    request = {"type": "FILE_REQUEST", "from": "TestScript", "filename": filename}
    send_message(sock, json.dumps(request))

    response = receive_message(sock)
    sock.close()

    if response:
        msg = json.loads(response)
        if msg["type"] == "FILE_TRANSFER":
            data = base64.b64decode(msg["data"])
            print(f"Received file: {msg['filename']}")
            print(f"  Size: {len(data)} bytes")
            if len(data) < 200:
                try:
                    print(f"  Content: {data.decode('utf-8')[:200]}")
                except UnicodeDecodeError:
                    print(f"  Content: (binary data)")

            # Verify hash
            received_hash = msg.get("hash", "")
            computed_hash = hashlib.sha256(data).hexdigest()
            if received_hash and received_hash == computed_hash:
                print(f"  Hash verified OK: {computed_hash[:32]}...")
            elif received_hash:
                print(f"  HASH MISMATCH!")
                print(f"    Expected: {received_hash}")
                print(f"    Got:      {computed_hash}")

            # Check signature is present
            sig = msg.get("signature", "")
            if sig:
                print(f"  Signature present: {sig[:32]}...")
            else:
                print(f"  No signature")

            print("FILE_REQUEST TEST PASSED!\n")
        elif msg["type"] == "ERROR":
            print(f"Error: {msg['message']}")
            print("FILE_REQUEST TEST FAILED (file not found)!\n")
    else:
        print("No response received")
        print("FILE_REQUEST TEST FAILED!\n")

def test_file_not_found():
    print("=" * 50)
    print("TEST 3: FILE_REQUEST for non-existent file")
    print("=" * 50)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))

    request = {"type": "FILE_REQUEST", "from": "TestScript", "filename": "does_not_exist.txt"}
    send_message(sock, json.dumps(request))

    response = receive_message(sock)
    sock.close()

    if response:
        msg = json.loads(response)
        if msg["type"] == "ERROR":
            print(f"Got expected error: {msg['message']}")
            print("FILE_NOT_FOUND TEST PASSED!\n")
        else:
            print(f"Unexpected response: {msg['type']}")
            print("FILE_NOT_FOUND TEST FAILED!\n")
    else:
        print("No response received")
        print("FILE_NOT_FOUND TEST FAILED!\n")

if __name__ == "__main__":
    # Create a test file in the shared directory
    shared_dir = os.path.expanduser("~/.p2pclient/shared")
    os.makedirs(shared_dir, exist_ok=True)
    test_file = os.path.join(shared_dir, "test_hello.txt")
    with open(test_file, "w") as f:
        f.write("Hello from the test script!")
    print(f"Created test file: {test_file}\n")

    # Run tests
    files = test_file_list()

    if files:
        test_file_request(files[0]["name"])

    test_file_not_found()

    # Cleanup test file
    os.remove(test_file)
    print("Cleaned up test file.")
