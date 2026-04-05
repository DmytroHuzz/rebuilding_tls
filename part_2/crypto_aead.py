# crypto_aead.py
#
# STAGE 3 — AEAD WITH AES-GCM
#
# WHAT THIS FILE DOES:
#   Replaces the manual AES-CTR + HMAC-SHA256 construction from Stages 1–2
#   with AES-GCM, an AEAD (Authenticated Encryption with Associated Data)
#   cipher.
#
# WHY AEAD:
#   In the previous stages we built encryption and authentication as two
#   separate layers — encrypt the data, then compute a MAC over it.  This
#   works, but it is easy to get wrong:
#     - you might MAC the wrong thing (plaintext instead of ciphertext)
#     - you might forget to include the nonce in the MAC input
#     - you might use the same key for both encryption and MAC
#     - you might decrypt before verifying (padding oracle attacks)
#
#   AEAD ciphers combine confidentiality and integrity into a single
#   primitive.  You call ONE function that encrypts AND authenticates.
#   There is no way to "forget" the MAC step or get the order wrong.
#
#   AES-GCM is the AEAD cipher used by TLS 1.3 (along with ChaCha20-Poly1305).
#
# WHY WE STILL IMPLEMENTED HMAC FIRST:
#   Educational clarity.  By building the MAC layer by hand, you can see
#   exactly what AEAD does internally: encrypt the data, authenticate it
#   (and any associated data), and produce a single sealed output.  Moving
#   to AEAD is the natural conclusion of that progression.
#
# RECORD FORMAT (Stage 3):
#
#     +-------------+--------------+-------------------------------+
#     | seq (8 B)   | nonce (12 B) | ciphertext_and_tag (N+16 B)   |
#     +-------------+--------------+-------------------------------+
#       big-endian    AES-GCM        AES-GCM output: encrypted data
#       uint64        nonce           + 16-byte authentication tag
#
#   Note: AES-GCM uses a 12-byte nonce (not 16 like AES-CTR).
#   Note: AES-GCM appends a 16-byte auth tag to the ciphertext internally.
#
# ASSOCIATED DATA:
#   We pass the 8-byte sequence number as "associated data" (AD) to AES-GCM.
#   Associated data is authenticated but NOT encrypted — the receiver must
#   supply the same AD to decrypt.  If the AD doesn't match, decryption
#   fails.  This binds each record to its position in the stream, just like
#   the sequence number in the HMAC input from Stage 2.
#
# WHAT IS STILL SIMPLIFIED:
#   - Key is hardcoded (pre-shared).
#   - No handshake — no key exchange, no session keys.
#   - No peer identity.
#   - This is still not real TLS because both sides still start with
#     pre-shared key material.

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Key — a single 256-bit key for AES-GCM.
# With AEAD, we do NOT need separate encryption and MAC keys — the
# algorithm handles both internally.
# ---------------------------------------------------------------------------
AEAD_KEY = b"AEAD_KEY_PART2_DEMO_FOR_AES_GCM!"  # 32 bytes → AES-256-GCM

# AES-GCM nonce length: 12 bytes is the recommended (and most efficient) size.
NONCE_LEN = 12

# Sequence number: 8 bytes (64-bit unsigned integer), same as Stage 2.
SEQ_LEN = 8


def protect_record_aead(seq: int, plaintext: bytes) -> bytes:
    """Seal a plaintext record with AES-GCM.

    Args:
        seq:       The current send-side sequence number.
        plaintext: The message to protect.

    Returns:
        seq (8 B) || nonce (12 B) || ciphertext_and_tag (N+16 B)
    """

    # Pack the sequence number as associated data.
    # The sequence number is authenticated but sent in the clear — the
    # receiver needs it to know which counter value to expect.
    seq_bytes = struct.pack("!Q", seq)

    # Generate a random 12-byte nonce for AES-GCM.
    nonce = os.urandom(NONCE_LEN)

    # Create an AESGCM instance with our key.
    aesgcm = AESGCM(AEAD_KEY)

    # Encrypt and authenticate in one call.
    # AESGCM.encrypt(nonce, data, associated_data) returns
    # ciphertext || 16-byte authentication tag as a single bytes object.
    # The associated_data (seq_bytes) is authenticated but NOT encrypted.
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, seq_bytes)

    print(f"  [crypto_aead] protect_record_aead:")
    print(f"    seq      = {seq}")
    print(f"    nonce    = {nonce.hex()}")
    print(
        f"    sealed   = {len(ciphertext_and_tag)} bytes "
        f"(plaintext {len(plaintext)} + tag 16)"
    )

    return seq_bytes + nonce + ciphertext_and_tag


def unprotect_record_aead(expected_seq: int, payload: bytes) -> bytes:
    """Verify and decrypt an AES-GCM sealed record.

    Args:
        expected_seq: The sequence number the receiver expects next.
        payload:      seq (8 B) || nonce (12 B) || ciphertext_and_tag.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError if the sequence number is wrong.
        cryptography.exceptions.InvalidTag if decryption/auth fails.
    """

    min_len = SEQ_LEN + NONCE_LEN + 16  # at least seq + nonce + tag
    if len(payload) < min_len:
        raise ValueError("Record too short")

    # Step 1: Parse the record.
    seq_bytes = payload[:SEQ_LEN]
    nonce = payload[SEQ_LEN : SEQ_LEN + NONCE_LEN]
    ciphertext_and_tag = payload[SEQ_LEN + NONCE_LEN :]

    # Step 2: Check the sequence number.
    (received_seq,) = struct.unpack("!Q", seq_bytes)
    if received_seq != expected_seq:
        print(
            f"  [crypto_aead] *** SEQUENCE MISMATCH: "
            f"got {received_seq}, expected {expected_seq} ***"
        )
        raise ValueError(
            f"Sequence number mismatch: got {received_seq}, expected {expected_seq}"
        )

    print(
        f"  [crypto_aead] Sequence number: {received_seq} "
        f"(expected {expected_seq}) — OK"
    )

    # Step 3: Decrypt and verify in one call.
    # AESGCM.decrypt(nonce, data, associated_data) verifies the auth tag
    # and decrypts.  If anything was tampered with — the ciphertext, the
    # tag, or the associated data — it raises InvalidTag.
    aesgcm = AESGCM(AEAD_KEY)
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, seq_bytes)

    print(f"  [crypto_aead] AEAD decryption: OK ({len(plaintext)} bytes)")

    return plaintext
