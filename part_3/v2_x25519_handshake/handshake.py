# handshake.py
#
# X25519 HANDSHAKE — v2
#
# WHAT THIS FILE DOES:
#   Implements the client-side and server-side handshake logic using
#   X25519, a modern elliptic-curve Diffie-Hellman function.
#
# WHAT CHANGED FROM v1 (CLASSIC DH):
#   X25519 removes the need to explicitly manage public prime/base
#   parameters in the handshake.  In v1 we had a big prime p and a
#   generator g that both sides needed to agree on.  X25519 uses a
#   fixed, standardized curve (Curve25519) — there is nothing to
#   negotiate.  The handshake becomes:
#
#     Client                              Server
#     ------                              ------
#     generate ephemeral keypair          generate ephemeral keypair
#
#     --- ClientHello [client_pub] --->
#                                         --- ServerHello [server_pub] --->
#
#     shared = X25519(client_priv,        shared = X25519(server_priv,
#                     server_pub)                         client_pub)
#
#   Both sides get the same 32-byte shared secret.
#
# WHY X25519:
#   - Fixed standard parameters — no prime/generator management.
#   - 32-byte keys — compact and efficient.
#   - Designed to be misuse-resistant (clamping, cofactor handling).
#   - Used in TLS 1.3, Signal, WireGuard, SSH, and many others.
#
# WHAT "EPHEMERAL" MEANS:
#   Each side generates a FRESH keypair for every handshake session.
#   The private key is never reused.  This gives us "ephemeral" key
#   exchange.  If an attacker later compromises a long-term secret,
#   they still cannot decrypt past sessions because the ephemeral
#   keys are gone.  This property is called FORWARD SECRECY.
#
#   (In our demo, we don't have long-term keys at all yet — that comes
#   with certificates in Part 4.  But the ephemeral pattern is already
#   in place.)
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication.  MITM is still possible.
#   - No derived session keys (that comes in v3).
#   - No record-layer protection after the handshake.

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


def client_handshake(sock) -> bytes:
    """Perform the client side of the X25519 handshake.

    Returns the 32-byte shared secret.
    """
    print("\n[handshake] Client: starting X25519 handshake")

    # Step 1: Generate an ephemeral X25519 keypair.
    # "Ephemeral" means we create a fresh keypair for this session only.
    # The private key never leaves this process and is discarded after use.
    client_private = X25519PrivateKey.generate()
    client_public = client_private.public_key()
    client_public_bytes = client_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Client public key: {hex_preview(client_public_bytes)}")

    # Step 2: Send ClientHello with our public key.
    client_hello = encode_message(
        [
            (TAG_X25519_PUBLIC, client_public_bytes),
        ]
    )
    send_record(sock, client_hello)
    print(f"  -> Sent ClientHello ({len(client_hello)} bytes)")

    # Step 3: Receive ServerHello with the server's public key.
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

    # Deserialize the server's public key from raw bytes.
    server_public = X25519PublicKey.from_public_bytes(server_public_bytes)

    # Step 4: Compute the shared secret.
    # X25519(client_private, server_public) = X25519(server_private, client_public)
    # This is the elliptic-curve equivalent of g^(ab) mod p from v1.
    shared_secret = client_private.exchange(server_public)

    print(f"  Shared secret computed: {hex_preview(shared_secret)}")
    print("[handshake] Client: handshake complete\n")

    return shared_secret


def server_handshake(sock) -> bytes:
    """Perform the server side of the X25519 handshake.

    Returns the 32-byte shared secret.
    """
    print("\n[handshake] Server: starting X25519 handshake")

    # Step 1: Generate an ephemeral X25519 keypair.
    server_private = X25519PrivateKey.generate()
    server_public = server_private.public_key()
    server_public_bytes = server_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Server public key: {hex_preview(server_public_bytes)}")

    # Step 2: Receive ClientHello with the client's public key.
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

    # Deserialize the client's public key from raw bytes.
    client_public = X25519PublicKey.from_public_bytes(client_public_bytes)

    # Step 3: Send ServerHello with our public key.
    server_hello = encode_message(
        [
            (TAG_X25519_PUBLIC, server_public_bytes),
        ]
    )
    send_record(sock, server_hello)
    print(f"  -> Sent ServerHello ({len(server_hello)} bytes)")

    # Step 4: Compute the shared secret.
    shared_secret = server_private.exchange(client_public)

    print(f"  Shared secret computed: {hex_preview(shared_secret)}")
    print("[handshake] Server: handshake complete\n")

    return shared_secret
