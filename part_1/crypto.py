# crypto.py
#
# AES-256 encryption in CTR (Counter) mode.
#
# HOW AES-CTR WORKS (simplified):
#   1. AES takes a 256-bit key and a 128-bit "nonce" (number used once).
#   2. It generates a stream of random-looking bytes (the "keystream").
#   3. It XORs the keystream with your plaintext → ciphertext.
#   4. To decrypt, XOR the same keystream with the ciphertext → plaintext.
#
#   Think of it like a one-time pad, except the "pad" is generated
#   deterministically from the key + nonce.
#
# IMPORTANT LIMITATION:
#   CTR mode provides CONFIDENTIALITY only — it hides the message content.
#   It does NOT provide INTEGRITY — an attacker can flip bits in the
#   ciphertext and the corresponding plaintext bits will flip silently.
#   We have no way to detect tampering.  (This is fixed in later versions
#   with HMAC or AES-GCM.)

import os
# `os.urandom(n)` reads `n` bytes from the OS's cryptographically secure
# random number generator (/dev/urandom on macOS/Linux).  This is the
# right way to generate random bytes for cryptographic use.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# `cryptography` is a well-maintained Python library for cryptographic
# operations.  We import:
#   Cipher     — the main object that combines an algorithm + mode
#   algorithms — the block cipher (AES in our case)
#   modes      — the mode of operation (CTR in our case)

# 32-byte (256-bit) shared key for AES-256.
# Both the client and server must know this same key in advance — this
# is called a PRE-SHARED KEY (PSK).
#
# WARNING: In real systems, NEVER hardcode a key in source code.
# This is for educational purposes only.  Later versions use
# Diffie-Hellman key exchange to agree on a key dynamically.
SHARED_KEY = b"0123456789ABCDEF0123456789ABCDEF"


def encrypt_message(plaintext: bytes) -> bytes:
    """Encrypt a plaintext message.  Returns nonce || ciphertext."""

    # Generate a random 16-byte (128-bit) nonce.
    # "Nonce" = "number used once".  Each encryption MUST use a unique nonce.
    # If you reuse a nonce with the same key, the security completely breaks:
    # an attacker can XOR two ciphertexts to cancel out the keystream and
    # recover the XOR of the two plaintexts.
    nonce = os.urandom(16)

    # Create a Cipher object configured for AES-256 in CTR mode.
    #   algorithms.AES(SHARED_KEY) — use AES with our 256-bit key
    #   modes.CTR(nonce)           — use Counter mode with this nonce
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CTR(nonce))

    # Get an encryptor object from the cipher.
    # The encryptor holds internal state (the counter) and produces
    # ciphertext as you feed it plaintext.
    encryptor = cipher.encryptor()

    # .update(data)  — encrypt the data (may return partial output)
    # .finalize()    — signal "no more data" and flush any remaining bytes
    # We concatenate them to get the complete ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # We prepend the nonce to the ciphertext so the receiver can
    # extract it and use the same nonce for decryption.
    #
    # Wire format:
    #   +----------------+---------------------+
    #   | nonce (16 B)   | ciphertext (N bytes) |
    #   +----------------+---------------------+
    return nonce + ciphertext


def decrypt_message(payload: bytes) -> bytes:
    """Decrypt a payload produced by encrypt_message().

    Expects the format: nonce (16 bytes) || ciphertext (remaining bytes).
    """

    # Split the payload: first 16 bytes are the nonce, rest is ciphertext.
    nonce = payload[:16]
    ciphertext = payload[16:]

    # Create the same Cipher with the same key and the nonce we just extracted.
    # AES-CTR decryption is identical to encryption — XOR with the same
    # keystream reverses the operation.
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
