# record_protection.py
#
# AEAD RECORD PROTECTION — carried forward from Part 3 v3.
#
# WHAT THIS FILE DOES:
#   Provides sequence-number + AES-GCM record protection.  The key is
#   supplied by the caller (derived via HKDF in key_schedule.py).
#
# WHAT IS NEW IN PART 4:
#   Nothing in the record layer itself.  Part 4 changes the handshake,
#   not the way application data is encrypted after the handshake.
#
# RECORD FORMAT (unchanged since Part 2):
#
#     +-------------+--------------+-------------------------------+
#     | seq (8 B)   | nonce (12 B) | ciphertext_and_tag (N+16 B)   |
#     +-------------+--------------+-------------------------------+

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
SEQ_LEN = 8


def protect_record(key: bytes, seq: int, plaintext: bytes) -> bytes:
    """Seal a plaintext record with AES-GCM."""
    seq_bytes = struct.pack("!Q", seq)
    nonce = os.urandom(NONCE_LEN)

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, seq_bytes)

    print(
        f"  [record] protect: seq={seq}, "
        f"nonce={nonce.hex()}, "
        f"sealed={len(ciphertext_and_tag)}B"
    )

    return seq_bytes + nonce + ciphertext_and_tag


def unprotect_record(key: bytes, expected_seq: int, payload: bytes) -> bytes:
    """Verify and decrypt an AES-GCM sealed record."""
    min_len = SEQ_LEN + NONCE_LEN + 16
    if len(payload) < min_len:
        raise ValueError("Record too short")

    seq_bytes = payload[:SEQ_LEN]
    nonce = payload[SEQ_LEN : SEQ_LEN + NONCE_LEN]
    ciphertext_and_tag = payload[SEQ_LEN + NONCE_LEN :]

    (received_seq,) = struct.unpack("!Q", seq_bytes)
    if received_seq != expected_seq:
        raise ValueError(
            f"Sequence mismatch: got {received_seq}, expected {expected_seq}"
        )

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, seq_bytes)

    print(f"  [record] unprotect: seq={received_seq}, OK ({len(plaintext)}B)")

    return plaintext
