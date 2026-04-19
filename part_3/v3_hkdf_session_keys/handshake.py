# handshake.py
#
# X25519 + HKDF HANDSHAKE — v3
#
# WHAT THIS FILE DOES:
#   Combines the X25519 key exchange from v2 with HKDF key derivation.
#   After the handshake, both sides have matching directional session keys
#   ready for the AEAD record layer.
#
# THE FULL PIPELINE (visible for the first time in v3):
#
#   client & server start with NO shared secret
#       → X25519 handshake exchanges ephemeral public keys
#       → both compute the same 32-byte shared secret
#       → HKDF derives client_write_key and server_write_key
#       → AEAD record layer protects application data
#
# WHAT CHANGED FROM v2:
#   v2 stopped after computing the shared secret.  v3 goes further:
#   it runs HKDF to produce actual session keys, then uses those keys
#   in the AEAD record layer from Part 2.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication.  This is still not real TLS because the handshake
#     is not authenticated — a man-in-the-middle can substitute public keys.
#   - No transcript hash.  Real TLS includes a hash of all handshake
#     messages in the key derivation.
#   - No HelloRetryRequest, no extensions, no cipher suite negotiation.

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from framing import send_record, recv_record
from handshake_messages import (
    encode_message,
    decode_message,
    TAG_X25519_PUBLIC,
)
from utils import hex_preview
from key_schedule import derive_session_keys


def client_handshake(sock) -> tuple:
    """Perform the client side of the X25519 + HKDF handshake.

    Returns (client_write_key, server_write_key) — each 32 bytes.
    """
    print("\n[handshake] Client: starting X25519 + HKDF handshake")

    # --- X25519 key exchange (same as v2) ---

    client_private = X25519PrivateKey.generate()
    client_public = client_private.public_key()
    client_public_bytes = client_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Client public key: {hex_preview(client_public_bytes)}")

    # Send ClientHello.
    client_hello = encode_message(
        [
            (TAG_X25519_PUBLIC, client_public_bytes),
        ]
    )
    send_record(sock, client_hello)
    print(f"  -> Sent ClientHello ({len(client_hello)} bytes)")

    # Receive ServerHello.
    server_hello_raw = recv_record(sock)
    fields = decode_message(server_hello_raw)
    server_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            server_public_bytes = value
    if server_public_bytes is None:
        raise ValueError("ServerHello missing X25519 public key")

    print(f"  <- Received ServerHello")
    print(f"  Server public key: {hex_preview(server_public_bytes)}")

    server_public = X25519PublicKey.from_public_bytes(server_public_bytes)

    # Compute shared secret.
    shared_secret = client_private.exchange(server_public)
    print(f"  Shared secret: {hex_preview(shared_secret)}")

    # --- NEW IN v3: derive session keys with HKDF ---
    # HKDF turns the raw shared secret into actual session keys for the
    # record layer.  This is where Part 3 goes beyond v2.
    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Client: handshake complete — session keys ready\n")

    return client_write_key, server_write_key


def server_handshake(sock) -> tuple:
    """Perform the server side of the X25519 + HKDF handshake.

    Returns (client_write_key, server_write_key) — each 32 bytes.
    """
    print("\n[handshake] Server: starting X25519 + HKDF handshake")

    # --- X25519 key exchange ---

    server_private = X25519PrivateKey.generate()
    server_public = server_private.public_key()
    server_public_bytes = server_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Server public key: {hex_preview(server_public_bytes)}")

    # Receive ClientHello.
    client_hello_raw = recv_record(sock)
    fields = decode_message(client_hello_raw)
    client_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            client_public_bytes = value
    if client_public_bytes is None:
        raise ValueError("ClientHello missing X25519 public key")

    print(f"  <- Received ClientHello")
    print(f"  Client public key: {hex_preview(client_public_bytes)}")

    client_public = X25519PublicKey.from_public_bytes(client_public_bytes)

    # Send ServerHello.
    server_hello = encode_message(
        [
            (TAG_X25519_PUBLIC, server_public_bytes),
        ]
    )
    send_record(sock, server_hello)
    print(f"  -> Sent ServerHello ({len(server_hello)} bytes)")

    # Compute shared secret.
    shared_secret = server_private.exchange(client_public)
    print(f"  Shared secret: {hex_preview(shared_secret)}")

    # --- Derive session keys ---
    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Server: handshake complete — session keys ready\n")

    return client_write_key, server_write_key
