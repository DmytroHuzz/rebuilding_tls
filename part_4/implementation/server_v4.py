# server_v4.py
#
# PART 4 — AUTHENTICATED TLS SERVER
#
# WHAT THIS FILE DOES:
#   Accepts one connection, performs an authenticated handshake (X25519
#   key exchange + certificate chain + CertificateVerify signature),
#   then exchanges application data protected by AES-GCM with derived keys.
#
# WHAT CHANGED FROM PART 3 v3:
#   The server now loads its long-term IDENTITY (RSA private key +
#   X.509 certificate chain) from disk, sends the chain to the client
#   during the handshake, and signs the exchanged EPHEMERAL X25519
#   public keys to prove it really is the holder of that identity.
#
#   Two distinct kinds of keys are involved (see handshake.py for the
#   full explanation):
#     - IDENTITY  (RSA, long-term, on disk)  → proves WHO we are
#     - EPHEMERAL (X25519, per-connection)   → agrees on session keys
#
# PREREQUISITES:
#   Run setup_certificates.py first to generate the certificate files.
#
# HOW TO RUN:
#   Terminal 1:  python server_v4.py
#   Terminal 2:  python client_v4.py

import sys
import os

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "part_3", "common")
)

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509

from framing import send_record, recv_record
from part_4.implementation.handshake import server_handshake
from part_4.implementation.record_protection import protect_record, unprotect_record

HOST = "127.0.0.1"
PORT = 10004

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")

# Sequence counters.
send_seq = 0
recv_seq = 0


def load_server_identity():
    """Load the server's long-term IDENTITY material from disk.

    Returns:
        (identity_private_key, identity_cert, intermediate_certs)

    `identity_private_key` is an RSA key — it is what the server uses to
    SIGN the CertificateVerify message during the handshake.  It must
    never leave the server.
    """
    with open(os.path.join(CERTS_DIR, "server_key.pem"), "rb") as f:
        identity_private_key = load_pem_private_key(f.read(), password=None)

    with open(os.path.join(CERTS_DIR, "server_cert.pem"), "rb") as f:
        identity_cert = x509.load_pem_x509_certificate(f.read())

    with open(os.path.join(CERTS_DIR, "intermediate_cert.pem"), "rb") as f:
        intermediate_cert = x509.load_pem_x509_certificate(f.read())

    return identity_private_key, identity_cert, [intermediate_cert]


print("=" * 60)
print("Part 4 — Authenticated TLS Server")
print("=" * 60)

server_identity_private_key, server_identity_cert, intermediate_certs = (
    load_server_identity()
)
print(f"Loaded identity certificate: {server_identity_cert.subject}")
print(f"Loaded {len(intermediate_certs)} intermediate certificate(s)")

import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # ==========================================
        # PHASE 1: AUTHENTICATED HANDSHAKE
        # ==========================================
        # We hand the IDENTITY material into the handshake.  The handshake
        # itself generates the per-connection EPHEMERAL X25519 keypair
        # internally and returns the derived session keys.
        client_write_key, server_write_key = server_handshake(
            conn,
            server_identity_private_key=server_identity_private_key,
            server_identity_cert=server_identity_cert,
            intermediate_certs=intermediate_certs,
        )

        # ==========================================
        # PHASE 2: APPLICATION DATA
        # ==========================================

        # --- Receive request (decrypted with client_write_key) ---
        print(f"--- Receiving request (expecting recv_seq={recv_seq}) ---")
        raw_request = recv_record(conn)

        try:
            request = unprotect_record(client_write_key, recv_seq, raw_request)
            recv_seq += 1
        except Exception as e:
            print(f"\n  *** REJECTED: {e} ***")
            print("  Connection closed — refusing to process invalid data.")
        else:
            print(f"\n  Decrypted request:\n  {request.decode('utf-8')}")

            # --- Send response (encrypted with server_write_key) ---
            print(f"--- Sending response (send_seq={send_seq}) ---")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n\r\n"
                "hello, client"
            ).encode("utf-8")

            protected = protect_record(server_write_key, send_seq, response)
            send_record(conn, protected)
            send_seq += 1
            print(f"  Record sent ({len(protected)} bytes on wire)")

print("\nDone.")
