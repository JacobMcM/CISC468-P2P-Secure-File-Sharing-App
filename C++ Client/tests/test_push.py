"""
Auto-accept push test: verify the C++ client correctly handles an inbound
file PUSH (requirement 3 -- the receiver consents before the transfer is
processed).

This test is fully unattended: it launches the C++ client as a subprocess,
feeds the device passphrase on stdin, then automatically drives the
consent prompts ('consent' + 'y'/'n') from Python so no human is needed.

Usage:
  cd "C++ Client"
  python3 tests/test_push.py
"""

import os
import sys
import time
import json
import socket
import struct
import base64
import hashlib
import subprocess
import threading

HOST = "127.0.0.1"
PORT = 5001
MY_NAME = "PushTester"
DEVICE_PASS = "autotestpass"

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.dirname(HERE)
BINARY = os.path.join(CLIENT_DIR, "p2pclient")


# ---------------- framed-message helpers ----------------

def send_message(sock, message):
    data = message.encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def receive_message(sock):
    length_data = b""
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            return None
        length_data += chunk
    length = struct.unpack("!I", length_data)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode("utf-8")


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))
    return sock


# ---------------- subprocess driver ----------------

class ClientProcess:
    """Spawns the C++ client and lets us read its stdout / write its stdin."""

    def __init__(self):
        if not os.path.exists(BINARY):
            raise FileNotFoundError(
                f"C++ binary not found at {BINARY}. Build it first (see READMECPP.md)."
            )
        self.proc = subprocess.Popen(
            [BINARY],
            cwd=CLIENT_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
        )
        self._lines = []
        self._read_pos = 0
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        for line in self.proc.stdout:
            with self._lock:
                self._lines.append(line)
            # Uncomment for debugging:
            # print("[client]", line.rstrip())

    def write(self, s):
        self.proc.stdin.write(s if s.endswith("\n") else s + "\n")
        self.proc.stdin.flush()

    def wait_for(self, needle, timeout=10.0):
        """Wait for `needle` to appear in stdout AFTER the last call."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for i in range(self._read_pos, len(self._lines)):
                    if needle in self._lines[i]:
                        self._read_pos = i + 1
                        return True
            time.sleep(0.05)
        return False

    def stop(self):
        try:
            self.write("quit")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


# ---------------- the actual push exchange ----------------

def push_file(filename, contents):
    sock = connect()
    consent = {
        "type": "CONSENT_REQUEST",
        "from": MY_NAME,
        "filename": filename,
        "filesize": len(contents),
    }
    send_message(sock, json.dumps(consent))
    return sock


def finish_push(sock, filename, contents):
    transfer = {
        "type": "FILE_TRANSFER",
        "from": MY_NAME,
        "filename": filename,
        "data": base64.b64encode(contents).decode(),
        "hash": hashlib.sha256(contents).hexdigest(),
        "signature": "",
    }
    send_message(sock, json.dumps(transfer))


# ---------------- main ----------------

def main():
    print("Launching C++ client subprocess...")
    client = ClientProcess()
    try:
        # Step 1: feed peer name + device passphrase to the prompts.
        if not client.wait_for("peer name", timeout=10) and not client.wait_for("name", timeout=2):
            print("WARN: never saw peer-name prompt; trying anyway")
        client.write(MY_NAME + "_local")
        if not client.wait_for("passphrase", timeout=10):
            print("WARN: never saw passphrase prompt; trying anyway")
        client.write(DEVICE_PASS)
        time.sleep(1.0)  # let it bind the listening socket

        # Helper that drives one push end-to-end with auto-consent
        def run_case(filename, contents, accept):
            print(f"\n--- {filename}: expect {'ACCEPT' if accept else 'REJECT'} ---")
            sock = push_file(filename, contents)

            # Wait for the client to print the consent prompt
            if not client.wait_for("CONSENT_REQUEST", timeout=10):
                print("  FAIL: client never printed CONSENT_REQUEST"); return False

            # Drive: consent -> y/n
            client.write("consent")
            time.sleep(0.2)
            client.write("y" if accept else "n")

            response = receive_message(sock)
            if response is None:
                print("  FAIL: no CONSENT_RESPONSE"); sock.close(); return False
            msg = json.loads(response)
            if msg.get("type") != "CONSENT_RESPONSE":
                print(f"  FAIL: got {msg.get('type')}"); sock.close(); return False
            if bool(msg.get("accepted")) != accept:
                print(f"  FAIL: accepted={msg.get('accepted')}"); sock.close(); return False

            if accept:
                finish_push(sock, filename, contents)
                time.sleep(0.5)  # let the client write+encrypt the file
            sock.close()
            print("  PASS")
            return True

        ok1 = run_case("push_test_accept.txt",
                       b"Hello from auto push test - should be accepted.",
                       accept=True)
        ok2 = run_case("push_test_reject.txt",
                       b"Should be rejected.",
                       accept=False)

        if ok1 and ok2:
            print("\nAll auto push tests PASSED")
            return 0
        print("\nAuto push tests FAILED")
        return 1
    finally:
        client.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConnectionRefusedError:
        print("ERROR: could not connect to C++ client on port 5001")
        sys.exit(1)
