# crypto_hmac.py
#
# STAGE 1 — ENCRYPT-THEN-MAC WITH AES-CTR + HMAC-SHA256
#
# WHAT THIS FILE DOES:
#   Adds INTEGRITY to the encrypted channel from Part 1.
#   In Part 1 we had AES-CTR encryption, which gives CONFIDENTIALITY only.
#   An attacker could flip ciphertext bits and the decryption would succeed
#   silently with corrupted plaintext.  That is the CTR bit-flipping attack.
#
#   Now we authenticate every encrypted record with HMAC-SHA256.
#   The receiver verifies the HMAC *before* decrypting.  If the ciphertext
#   was tampered with, the HMAC will not match and the record is rejected.
#
# CONSTRUCTION — ENCRYPT-THEN-MAC:
#   1. Encrypt the plaintext with AES-CTR → (nonce, ciphertext)
#   2. Compute HMAC-SHA256 over (nonce || ciphertext) using a separate MAC key
#   3. Send: nonce || ciphertext || tag
#
#   Why encrypt-then-MAC?
#     - The MAC covers the *ciphertext*, not the plaintext.
#     - The receiver can verify authenticity without decrypting.
#     - This is the construction recommended by modern cryptographic practice.
#     - The alternative (MAC-then-encrypt) has subtle vulnerabilities, e.g.
#       padding oracles in CBC-based schemes.
#
# RECORD FORMAT:
#
#     +----------------+---------------------+----------------+
#     | nonce (16 B)   | ciphertext (N bytes) | tag (32 bytes) |
#     +----------------+---------------------+----------------+
#       AES-CTR nonce    encrypted plaintext    HMAC-SHA256
#
# KEY MANAGEMENT:
#   We use TWO separate hardcoded keys:
#     - ENC_KEY for AES-CTR encryption
#     - MAC_KEY for HMAC-SHA256
#
#   Using separate keys for encryption and authentication is standard practice.
#   If you used the same key for both, certain constructions can become
#   vulnerable to subtle attacks.
#
# WHAT IS STILL SIMPLIFIED:
#   - Keys are hardcoded (pre-shared).  No key exchange.
#   - No sequence numbers — records can be replayed or reordered.
#   - No handshake — both sides just start sending.
#   - This is NOT a replacement for real TLS.

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Keys — hardcoded for educational purposes.
# In a real protocol, these would be derived from a key exchange (e.g.,
# Diffie-Hellman), not embedded in source code.
# ---------------------------------------------------------------------------

# 32-byte (256-bit) key for AES-256-CTR encryption.
ENC_KEY = b"0123456789ABCDEF0123456789ABCDEF"

# 32-byte key for HMAC-SHA256.  Separate from the encryption key.
MAC_KEY = b"HMAC_KEY_FOR_PART2_DEMO_1234567"

# HMAC-SHA256 produces a 32-byte (256-bit) tag.
TAG_LEN = 32

# AES-CTR nonce is 16 bytes (128 bits).
NONCE_LEN = 16


def encrypt_then_mac(plaintext: bytes) -> bytes:
    """Encrypt a plaintext and append an HMAC tag.

    Returns: nonce (16 B) || ciphertext (N B) || tag (32 B)
    """

    # Step 1: Generate a fresh random nonce for AES-CTR.
    # A new nonce MUST be used for every record — reusing a nonce with
    # the same key completely breaks CTR-mode security.
    nonce = os.urandom(NONCE_LEN)

    # Step 2: Encrypt the plaintext with AES-256-CTR.
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Step 3: Compute HMAC-SHA256 over (nonce || ciphertext).
    # New in Part 2: we authenticate the encrypted record before sending it.
    # The HMAC input includes the nonce so an attacker cannot swap nonces
    # between records without detection.
    mac_input = nonce + ciphertext
    tag = hmac.new(MAC_KEY, mac_input, hashlib.sha256).digest()

    print(f"  [crypto_hmac] encrypt_then_mac:")
    print(f"    nonce    = {nonce.hex()[:32]}...")
    print(f"    ct_len   = {len(ciphertext)} bytes")
    print(f"    tag      = {tag.hex()[:32]}...")

    # Step 4: Assemble the wire format.
    return nonce + ciphertext + tag


def verify_then_decrypt(payload: bytes) -> bytes:
    """Verify the HMAC tag, then decrypt if valid.

    Expects: nonce (16 B) || ciphertext (N B) || tag (32 B)
    Raises ValueError if the tag does not match.
    """

    # Step 1: Parse the record into its components.
    # The tag is always the last 32 bytes.  The nonce is the first 16.
    # Everything in between is ciphertext.
    if len(payload) < NONCE_LEN + TAG_LEN:
        raise ValueError("Record too short to contain nonce + tag")

    nonce = payload[:NONCE_LEN]
    ciphertext = payload[NONCE_LEN:-TAG_LEN]
    received_tag = payload[-TAG_LEN:]

    # Step 2: Recompute the HMAC over (nonce || ciphertext).
    mac_input = nonce + ciphertext
    expected_tag = hmac.new(MAC_KEY, mac_input, hashlib.sha256).digest()

    # Step 3: Compare tags using constant-time comparison.
    # hmac.compare_digest() prevents timing side-channel attacks.
    # A naive `==` comparison can leak information about which byte
    # position differs first, allowing an attacker to forge a valid
    # tag byte by byte.
    if not hmac.compare_digest(received_tag, expected_tag):
        print("  [crypto_hmac] *** MAC VERIFICATION FAILED — record rejected ***")
        raise ValueError("HMAC verification failed — record has been tampered with")

    print("  [crypto_hmac] MAC verification: OK")

    # Step 4: Decrypt only after verification succeeds.
    # This is the key benefit of encrypt-then-MAC: we never process
    # unauthenticated ciphertext.
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
