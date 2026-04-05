# crypto_hmac_seq.py
#
# STAGE 2 — ENCRYPT-THEN-MAC WITH SEQUENCE NUMBERS
#
# WHAT THIS FILE DOES:
#   Builds on crypto_hmac.py (Stage 1) by adding an 8-byte SEQUENCE NUMBER
#   to every record.  The sequence number is included in the HMAC input,
#   so the integrity check now covers record ORDER and POSITION, not just
#   content.
#
# WHY SEQUENCE NUMBERS MATTER:
#   Without sequence numbers, an attacker sitting on the wire can:
#     - REPLAY an old record (resend a legitimate record a second time)
#     - REORDER records (swap record #3 and record #5)
#     - DROP records (remove record #4 entirely)
#   … and the receiver cannot tell, because each individual HMAC still
#   verifies correctly.  The MAC only proves "this record was created by
#   someone with the key" — it says nothing about *when* or *where* in the
#   stream the record belongs.
#
#   By including a monotonically increasing counter in the MAC input, we
#   bind each record to its expected position.  If an attacker replays
#   record #2 in the slot where record #5 is expected, the HMAC will not
#   match because the counter value is wrong.
#
# CAVEATS (be honest — this is educational code):
#   - This prevents simple replay and reorder within a single session.
#   - It does NOT provide cross-session replay protection (for that you
#     need fresh per-session keys, which requires a handshake — Part 3+).
#   - The sequence number is sent in the clear.  That's fine here — it is
#     authenticated by the HMAC, so tampering with it causes rejection.
#
# RECORD FORMAT (Stage 2):
#
#     +-------------+----------------+---------------------+----------------+
#     | seq (8 B)   | nonce (16 B)   | ciphertext (N bytes) | tag (32 bytes) |
#     +-------------+----------------+---------------------+----------------+
#       big-endian    AES-CTR nonce    encrypted plaintext    HMAC-SHA256
#       uint64
#
# HMAC INPUT:
#
#     seq (8 B) || nonce (16 B) || ciphertext (N B)
#
# WHAT IS STILL SIMPLIFIED:
#   - Keys are hardcoded (pre-shared).
#   - No handshake — no fresh session keys.
#   - No peer identity / trust model.

import os
import hmac
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Keys — same as crypto_hmac.py, hardcoded for education.
# ---------------------------------------------------------------------------
ENC_KEY = b"0123456789ABCDEF0123456789ABCDEF"
MAC_KEY = b"HMAC_KEY_FOR_PART2_DEMO_1234567"

TAG_LEN = 32  # HMAC-SHA256 output: 32 bytes (256 bits)
NONCE_LEN = 16  # AES-CTR nonce: 16 bytes (128 bits)
SEQ_LEN = 8  # Sequence number: 8 bytes (64-bit unsigned integer)


def protect_record(seq: int, plaintext: bytes) -> bytes:
    """Encrypt a plaintext record and attach a sequence-aware HMAC tag.

    Args:
        seq:       The current send-side sequence number (0, 1, 2, …).
        plaintext: The message to protect.

    Returns:
        seq (8 B) || nonce (16 B) || ciphertext (N B) || tag (32 B)
    """

    # Pack the sequence number as an 8-byte big-endian unsigned integer.
    # "!Q" = network byte order, unsigned 64-bit.
    seq_bytes = struct.pack("!Q", seq)

    # Generate a fresh AES-CTR nonce.
    nonce = os.urandom(NONCE_LEN)

    # Encrypt the plaintext.
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Compute HMAC over (seq || nonce || ciphertext).
    # The sequence number is included in the MAC input so the integrity
    # check also covers record order/position in the stream.
    mac_input = seq_bytes + nonce + ciphertext
    tag = hmac.new(MAC_KEY, mac_input, hashlib.sha256).digest()

    print(f"  [crypto_hmac_seq] protect_record:")
    print(f"    seq      = {seq}")
    print(f"    nonce    = {nonce.hex()[:32]}...")
    print(f"    ct_len   = {len(ciphertext)} bytes")
    print(f"    tag      = {tag.hex()[:32]}...")

    return seq_bytes + nonce + ciphertext + tag


def verify_and_unprotect(expected_seq: int, payload: bytes) -> bytes:
    """Verify the HMAC and sequence number, then decrypt.

    Args:
        expected_seq: The sequence number the receiver expects next.
        payload:      The raw bytes received: seq || nonce || ct || tag.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError if the MAC is invalid or the sequence number is wrong.
    """

    min_len = SEQ_LEN + NONCE_LEN + TAG_LEN
    if len(payload) < min_len:
        raise ValueError("Record too short")

    # Step 1: Parse the record.
    seq_bytes = payload[:SEQ_LEN]
    nonce = payload[SEQ_LEN : SEQ_LEN + NONCE_LEN]
    ciphertext = payload[SEQ_LEN + NONCE_LEN : -TAG_LEN]
    received_tag = payload[-TAG_LEN:]

    # Step 2: Recompute HMAC over (seq || nonce || ciphertext).
    mac_input = seq_bytes + nonce + ciphertext
    expected_tag = hmac.new(MAC_KEY, mac_input, hashlib.sha256).digest()

    # Step 3: Constant-time tag comparison.
    if not hmac.compare_digest(received_tag, expected_tag):
        print("  [crypto_hmac_seq] *** MAC VERIFICATION FAILED ***")
        raise ValueError("HMAC verification failed — record tampered or replayed")

    print("  [crypto_hmac_seq] MAC verification: OK")

    # Step 4: Check the sequence number matches what we expect.
    # Even though the MAC already covers the sequence number (so an
    # attacker cannot change it without invalidating the MAC), we still
    # explicitly verify that it matches our counter.  This catches
    # replayed or reordered records that carry a valid MAC but belong
    # to a different position in the stream.
    (received_seq,) = struct.unpack("!Q", seq_bytes)
    if received_seq != expected_seq:
        print(
            f"  [crypto_hmac_seq] *** SEQUENCE MISMATCH: "
            f"got {received_seq}, expected {expected_seq} ***"
        )
        raise ValueError(
            f"Sequence number mismatch: got {received_seq}, expected {expected_seq}"
        )

    print(
        f"  [crypto_hmac_seq] Sequence number: {received_seq} (expected {expected_seq}) — OK"
    )

    # Step 5: Decrypt.
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
