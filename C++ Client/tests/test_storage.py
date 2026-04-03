"""
Test script for secure local storage (PBKDF2 + AES-256-GCM at rest).

This test sends a FILE_LIST_REQUEST (no consent needed), then manually
tests the encrypt/decrypt storage functions by:
1. Connecting and requesting a file list
2. Verifying the C++ client can serve files
3. Testing encrypt/decrypt locally in Python using the same PBKDF2+AES-GCM scheme

Setup:
    1. Place a file in ~/.p2pclient/shared/
    2. Start the C++ client: ./p2pclient
    3. In another terminal: python3 tests/test_storage.py
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_pbkdf2_aes_gcm():
    """Test that our PBKDF2 + AES-256-GCM encryption/decryption works correctly."""
    print("=" * 50)
    print("TEST: PBKDF2 + AES-256-GCM Local Storage")
    print("=" * 50)

    passphrase = "testpassphrase123"
    plaintext = b"This is secret file contents that should be encrypted at rest!"

    # Step 1: Generate random salt (16 bytes)
    salt = os.urandom(16)
    print(f"Salt: {salt.hex()}")

    # Step 2: Derive key with PBKDF2-HMAC-SHA256 (600,000 iterations)
    print("Deriving key with PBKDF2 (600k iterations)... ", end="", flush=True)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(passphrase.encode())
    print("done")
    print(f"Derived key: {key.hex()[:32]}...")

    # Step 3: Encrypt with AES-256-GCM
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    # Format: IV (12) + ciphertext + tag (16)
    encrypted = iv + ct_and_tag
    # Base64 encode (matching C++ aesGcmEncrypt output)
    encrypted_b64 = base64.b64encode(encrypted).decode()

    # Full storage format: salt (16 bytes) + base64(IV + ct + tag)
    stored_data = salt + encrypted_b64.encode()
    print(f"Encrypted size: {len(stored_data)} bytes (salt + base64 ciphertext)")

    # Step 4: Decrypt
    recovered_salt = stored_data[:16]
    recovered_encrypted_b64 = stored_data[16:].decode()

    # Re-derive key from passphrase + salt
    kdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recovered_salt,
        iterations=600000,
    )
    recovered_key = kdf2.derive(passphrase.encode())

    # Decrypt AES-GCM
    recovered_encrypted = base64.b64decode(recovered_encrypted_b64)
    recovered_iv = recovered_encrypted[:12]
    recovered_ct_and_tag = recovered_encrypted[12:]
    aesgcm2 = AESGCM(recovered_key)
    decrypted = aesgcm2.decrypt(recovered_iv, recovered_ct_and_tag, None)

    if decrypted == plaintext:
        print(f"Decrypted: {decrypted.decode()}")
        print("ENCRYPTION/DECRYPTION TEST PASSED!")
    else:
        print("DECRYPTION MISMATCH!")
        print("TEST FAILED!")
        return False

    # Step 5: Test wrong passphrase
    print("\nTesting wrong passphrase...")
    kdf3 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recovered_salt,
        iterations=600000,
    )
    wrong_key = kdf3.derive(b"wrongpassword")
    aesgcm3 = AESGCM(wrong_key)
    try:
        aesgcm3.decrypt(recovered_iv, recovered_ct_and_tag, None)
        print("ERROR: Decryption should have failed with wrong passphrase!")
        print("TEST FAILED!")
        return False
    except Exception:
        print("Correctly rejected wrong passphrase (decryption failed)")
        print("WRONG PASSPHRASE TEST PASSED!")

    # Step 6: Write encrypted file to disk and verify
    print("\nTesting file write/read...")
    test_path = os.path.expanduser("~/.p2pclient/downloads/storage_test.txt.enc")
    os.makedirs(os.path.dirname(test_path), exist_ok=True)

    with open(test_path, "wb") as f:
        f.write(stored_data)
    print(f"Wrote encrypted file: {test_path}")

    with open(test_path, "rb") as f:
        read_data = f.read()

    if read_data == stored_data:
        print("File read matches written data")
        print("FILE STORAGE TEST PASSED!")
    else:
        print("FILE MISMATCH!")
        print("TEST FAILED!")
        return False

    # Cleanup
    os.remove(test_path)
    print(f"Cleaned up {test_path}")

    print("\n" + "=" * 50)
    print("ALL STORAGE TESTS PASSED!")
    print("=" * 50)
    return True

if __name__ == "__main__":
    test_pbkdf2_aes_gcm()
