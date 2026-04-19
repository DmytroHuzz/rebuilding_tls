# handshake.py
#
# CLASSIC DIFFIE-HELLMAN HANDSHAKE — v1
#
# WHAT THIS FILE DOES:
#   Implements the client-side and server-side handshake logic for
#   classic Diffie-Hellman key exchange.
#
# HANDSHAKE FLOW:
#
#   Client                              Server
#   ------                              ------
#   pick p and g
#   generate private_a
#   compute  public_A = g^a mod p
#
#   --- ClientHello --->
#   [p, g, client_public]
#                                       parse p, g, client_public
#                                       generate private_b
#                                       compute  public_B = g^b mod p
#                                       --- ServerHello --->
#                                       [server_public]
#
#   shared = public_B^a mod p           shared = public_A^b mod p
#
#   Both sides now have the same shared secret: g^(ab) mod p
#
# DESIGN NOTES:
#   - The client sends p and g explicitly in the ClientHello.  In a real
#     protocol the server would validate these parameters carefully (e.g.,
#     check that p is a safe prime, that g is a valid generator, etc.).
#     We skip deep validation here to keep the code educational.
#   - p and g are PUBLIC.  They are not secret.  Anyone can see them on
#     the wire and that is perfectly fine — the security of Diffie-Hellman
#     does not depend on p and g being hidden.
#   - The public DH values (A and B) are also public.  Only the private
#     exponents (a and b) are secret — and they are never transmitted.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication.  An attacker in the middle can intercept both
#     public values and substitute their own (MITM attack).
#   - No parameter validation on the server side.
#   - No derived session keys — the raw shared secret is just printed.
#   - No record-layer encryption after the handshake.

import sys
import os

# Allow imports from the common/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

from framing import send_record, recv_record
from handshake_messages import (
    encode_message,
    decode_message,
    TAG_DH_P,
    TAG_DH_G,
    TAG_DH_PUBLIC,
)
from utils import hex_preview
from dh_math import (
    DH_PRIME,
    DH_GENERATOR,
    generate_private_exponent,
    compute_public_value,
    compute_shared_secret,
    int_to_bytes,
    bytes_to_int,
)


def client_handshake(sock) -> bytes:
    """Perform the client side of the classic DH handshake.

    The client picks the public parameters (p, g) and sends them to the
    server along with its own public DH value.  The server uses those
    parameters to compute its own public value and sends it back.

    Returns the shared secret as bytes.
    """
    print("\n[handshake] Client: starting classic DH handshake")

    # The client chooses p and g.  These are PUBLIC — not secret.
    # Anyone on the wire can see them, and that is perfectly fine.
    # The security of DH depends on the hardness of the discrete
    # logarithm problem, not on hiding p and g.
    p = DH_PRIME
    g = DH_GENERATOR

    print(f"  Public parameters (chosen by client, sent to server):")
    print(f"    p = {str(p)[:40]}... ({p.bit_length()} bits)")
    print(f"    g = {g}")

    # Step 1: Generate client's private exponent and public value.
    # The private exponent is the ONE thing that stays secret.
    client_private = generate_private_exponent()
    client_public = compute_public_value(client_private, g, p)
    client_public_bytes = int_to_bytes(client_public)

    print(
        f"  Client private exponent: (secret — never sent, {client_private.bit_length()} bits)"
    )
    print(f"  Client public value A:   {hex_preview(client_public_bytes)}")

    # Step 2: Send ClientHello with p, g, and our public value.
    # All three are public.  The private exponent is NOT included.
    p_bytes = int_to_bytes(p)
    g_bytes = int_to_bytes(g)

    client_hello = encode_message(
        [
            (TAG_DH_P, p_bytes),
            (TAG_DH_G, g_bytes),
            (TAG_DH_PUBLIC, client_public_bytes),
        ]
    )
    send_record(sock, client_hello)
    print(f"  -> Sent ClientHello ({len(client_hello)} bytes)")
    print(
        f"     Contains: p ({len(p_bytes)}B), g ({len(g_bytes)}B), "
        f"A ({len(client_public_bytes)}B)"
    )

    # Step 3: Receive ServerHello with the server's public value.
    server_hello_raw = recv_record(sock)
    fields = decode_message(server_hello_raw)
    server_public_bytes = None
    for tag, value in fields:
        if tag == TAG_DH_PUBLIC:
            server_public_bytes = value
    if server_public_bytes is None:
        raise ValueError("ServerHello missing DH public value")

    server_public = bytes_to_int(server_public_bytes)
    print(f"  <- Received ServerHello")
    print(f"  Server public value B:   {hex_preview(server_public_bytes)}")

    # Step 4: Compute the shared secret.
    # shared = B^a mod p = (g^b)^a mod p = g^(ab) mod p
    shared_int = compute_shared_secret(server_public, client_private, p)
    shared_bytes = int_to_bytes(shared_int)

    print(f"  Shared secret computed:  {hex_preview(shared_bytes)}")
    print("[handshake] Client: handshake complete\n")

    return shared_bytes


def server_handshake(sock) -> bytes:
    """Perform the server side of the classic DH handshake.

    The server receives p, g, and client_public from the ClientHello,
    uses those parameters to generate its own keypair, and sends its
    public value back.

    Returns the shared secret as bytes.
    """
    print("\n[handshake] Server: starting classic DH handshake")

    # Step 1: Receive ClientHello — parse p, g, and client's public value.
    # The server does NOT assume any particular p or g.  It uses whatever
    # the client proposes.  (In a production system, the server would
    # validate that p is a safe prime and g is a proper generator.
    # We skip that here for clarity.)
    client_hello_raw = recv_record(sock)
    fields = decode_message(client_hello_raw)

    p_bytes = None
    g_bytes = None
    client_public_bytes = None
    for tag, value in fields:
        if tag == TAG_DH_P:
            p_bytes = value
        elif tag == TAG_DH_G:
            g_bytes = value
        elif tag == TAG_DH_PUBLIC:
            client_public_bytes = value

    if p_bytes is None:
        raise ValueError("ClientHello missing DH prime (p)")
    if g_bytes is None:
        raise ValueError("ClientHello missing DH generator (g)")
    if client_public_bytes is None:
        raise ValueError("ClientHello missing DH public value (A)")

    # Deserialize the parameters from bytes.
    p = bytes_to_int(p_bytes)
    g = bytes_to_int(g_bytes)
    client_public = bytes_to_int(client_public_bytes)

    print(f"  <- Received ClientHello")
    print(f"  Public parameters (received from client):")
    print(f"    p = {str(p)[:40]}... ({p.bit_length()} bits)")
    print(f"    g = {g}")
    print(f"  Client public value A:   {hex_preview(client_public_bytes)}")

    # Step 2: Generate server's private exponent and public value
    # using the p and g received from the client.
    server_private = generate_private_exponent()
    server_public = compute_public_value(server_private, g, p)
    server_public_bytes = int_to_bytes(server_public)

    print(
        f"  Server private exponent: (secret — never sent, {server_private.bit_length()} bits)"
    )
    print(f"  Server public value B:   {hex_preview(server_public_bytes)}")

    # Step 3: Send ServerHello with our public value.
    # Only B is sent — p and g are already known from the ClientHello.
    server_hello = encode_message(
        [
            (TAG_DH_PUBLIC, server_public_bytes),
        ]
    )
    send_record(sock, server_hello)
    print(f"  -> Sent ServerHello ({len(server_hello)} bytes)")
    print(f"     Contains: B ({len(server_public_bytes)}B)")

    # Step 4: Compute the shared secret.
    # shared = A^b mod p = (g^a)^b mod p = g^(ab) mod p
    shared_int = compute_shared_secret(client_public, server_private, p)
    shared_bytes = int_to_bytes(shared_int)

    print(f"  Shared secret computed:  {hex_preview(shared_bytes)}")
    print("[handshake] Server: handshake complete\n")

    return shared_bytes
