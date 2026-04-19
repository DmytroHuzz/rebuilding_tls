# record_protection.py
#
# AEAD RECORD PROTECTION — adapted from Part 2 with derived session keys.
#
# WHAT THIS FILE DOES:
#   Provides the same sequence-number + AES-GCM record protection that
#   Part 2's crypto_aead.py offered, but now the key is a parameter
#   instead of a hardcoded constant.
#
# WHAT CHANGED FROM PART 2:
#   In Part 2, `crypto_aead.py` had:
#     AEAD_KEY = b"AEAD_KEY_PART2_DEMO_FOR_AES_GCM!"   # hardcoded
#
#   In Part 3, the AEAD key comes from HKDF (see key_schedule.py).
#   The protect/unprotect functions now take the key as a parameter.
#
# RECORD FORMAT (unchanged from Part 2, Stage 3):
#
#     +-------------+--------------+-------------------------------+
#     | seq (8 B)   | nonce (12 B) | ciphertext_and_tag (N+16 B)   |
#     +-------------+--------------+-------------------------------+
#       big-endian    AES-GCM        encrypted data + 16-byte tag
#       uint64        nonce
#
#   The sequence number is passed as associated data — authenticated but
#   not encrypted.
#
# WHAT IS STILL SIMPLIFIED:
#   - No re-keying (real TLS can update keys mid-session).
#   - No key usage limits enforcement.

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # AES-GCM recommended nonce size
SEQ_LEN = 8  # 64-bit sequence number


def protect_record(key: bytes, seq: int, plaintext: bytes) -> bytes:
    """Seal a plaintext record with AES-GCM using the given key.

    Args:
        key:       32-byte AES-GCM key (from HKDF).
        seq:       Current send-side sequence number.
        plaintext: The message to protect.

    Returns:
        seq (8 B) || nonce (12 B) || ciphertext_and_tag (N+16 B)
    """
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
    """Verify and decrypt an AES-GCM sealed record.

    Args:
        key:          32-byte AES-GCM key (from HKDF).
        expected_seq: The sequence number the receiver expects next.
        payload:      seq (8 B) || nonce (12 B) || ciphertext_and_tag.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError if the sequence number is wrong.
        cryptography.exceptions.InvalidTag if AEAD verification fails.
    """
    min_len = SEQ_LEN + NONCE_LEN + 16  # seq + nonce + at least the tag
    if len(payload) < min_len:
        raise ValueError("Record too short")

    seq_bytes = payload[:SEQ_LEN]
    nonce = payload[SEQ_LEN : SEQ_LEN + NONCE_LEN]
    ciphertext_and_tag = payload[SEQ_LEN + NONCE_LEN :]

    # Check sequence number.
    (received_seq,) = struct.unpack("!Q", seq_bytes)
    if received_seq != expected_seq:
        raise ValueError(
            f"Sequence mismatch: got {received_seq}, expected {expected_seq}"
        )

    # Decrypt and verify in one atomic operation.
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, seq_bytes)

    print(f"  [record] unprotect: seq={received_seq}, OK ({len(plaintext)}B)")

    return plaintext
