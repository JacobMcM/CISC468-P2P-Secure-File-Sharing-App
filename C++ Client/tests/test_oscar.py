"""
oscar - passive eavesdropper demo (tcpdump version).

prints the exact commands to run a clean wire-capture demo proving that
file transfers between alice and bob are encrypted on the wire.
"""

STEPS = """
oscar - passive network eavesdropper
watches the wire while alice and bob talk.
the eke handshake is visible as json envelopes (dh values encrypted under
the password). once the session key is established, the file request and
file transfer are pure aes-gcm ciphertext - no filename, no contents.

setup (any terminal):
  rm -rf ~/.p2pclient-5001 ~/.p2pclient-5002
  mkdir -p ~/.p2pclient-5001/shared
  echo 'TOP SECRET: launch codes 12345' > ~/.p2pclient-5001/shared/secret.txt

terminal 3 - oscar (start FIRST so the handshake is captured):
  sudo tcpdump -i lo0 -A -s 0 'port 5001 and length > 0' --immediate-mode

terminal 1 - alice:
  cd "C++ Client" && ./p2pclient "Alice" 5001
  passphrase: demo1
  >  password    ->  Bob / ab123

terminal 2 - bob:
  cd "C++ Client" && ./p2pclient "Bob" 5002
  passphrase: demo2
  >  password    ->  Alice / ab123
  >  handshake   ->  Alice
  >  request     ->  Alice / secret.txt

terminal 1 - alice approves:
  >  consent     ->  y

terminal 3: ctrl+c, screenshot the capture.

what to point at in the screenshot:
  - early packets: readable json with "type":"EKE_1".."EKE_4"
  - later packets: opaque base64 blobs - no "secret.txt", no "launch"
  - grep -i 'secret.txt\\|launch' on the capture: zero hits = confidentiality
"""

if __name__ == "__main__":
    print(STEPS)
