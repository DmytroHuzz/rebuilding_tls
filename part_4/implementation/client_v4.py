# client_v4.py
#
# PART 4 — AUTHENTICATED TLS CLIENT
#
# WHAT THIS FILE DOES:
#   Connects to the server, performs an authenticated handshake, then
#   exchanges application data protected by AES-GCM with derived keys.
#
# WHAT CHANGED FROM PART 3 v3:
#   The client now loads the trusted root certificate, and during the
#   handshake it verifies the server's IDENTITY (X.509 chain) and the
#   CertificateVerify signature.  This closes the man-in-the-middle
#   vulnerability from Part 3.
#
# TWO KINDS OF KEYS THE CLIENT DEALS WITH:
#   - IDENTITY (incoming, RSA): never owned by the client; only verified.
#       The client trusts the root CA and uses it to validate the server's
#       certificate chain, then trusts the RSA public key inside the
#       server cert.
#   - EPHEMERAL (X25519): the client GENERATES its own per-connection
#       keypair, sends the public half in ClientHello, and uses the
#       resulting shared secret to derive AES-GCM session keys.
#
# THE AUTHENTICATION FLOW:
#   1. Generate EPHEMERAL X25519 keypair, send public half in ClientHello.
#   2. Receive server's EPHEMERAL X25519 public key in ServerHello.
#   3. Receive server's IDENTITY chain + CertificateVerify in ServerAuth.
#   4. Verify the chain back to the trusted root  → trust the RSA pubkey.
#   5. Verify CertificateVerify with that RSA pubkey
#      → proves the peer holds the IDENTITY private key
#      AND that it signed THESE specific ephemeral keys.
#   6. Derive session keys via HKDF from the X25519 shared secret.
#
# PREREQUISITES:
#   Run setup_certificates.py first to generate the certificate files.
#
# HOW TO RUN:
#   Terminal 1:  python server_v4.py
#   Terminal 2:  python client_v4.py

import sys
import os
import socket

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "part_3", "common")
)

from cryptography import x509

from framing import send_record, recv_record
from part_4.implementation.handshake import client_handshake
from part_4.implementation.record_protection import protect_record, unprotect_record

HOST = "127.0.0.1"
PORT = 10004
DNS_NAME = "localhost"

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")

# Sequence counters.
send_seq = 0
recv_seq = 0

# Application request.
request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")


def load_trusted_root():
    """Load the root CA certificate that the client trusts."""
    with open(os.path.join(CERTS_DIR, "root_cert.pem"), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


print("=" * 60)
print("Part 4 — Authenticated TLS Client")
print("=" * 60)

trusted_root = load_trusted_root()
print(f"Loaded trusted root: {trusted_root.subject}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # ==========================================
    # PHASE 1: AUTHENTICATED HANDSHAKE
    # ==========================================
    # The handshake now verifies the server's certificate chain and
    # signature before deriving session keys.
    client_write_key, server_write_key = client_handshake(
        client,
        trusted_root=trusted_root,
        dns_name=DNS_NAME,
    )

    # ==========================================
    # PHASE 2: APPLICATION DATA
    # ==========================================

    # --- Send request (encrypted with client_write_key) ---
    print(f"--- Sending request (send_seq={send_seq}) ---")
    protected = protect_record(client_write_key, send_seq, request)
    send_record(client, protected)
    send_seq += 1
    print(f"  Record sent ({len(protected)} bytes on wire)")

    # --- Receive response (decrypted with server_write_key) ---
    print(f"\n--- Receiving response (expecting recv_seq={recv_seq}) ---")
    raw_response = recv_record(client)

    try:
        response = unprotect_record(server_write_key, recv_seq, raw_response)
        recv_seq += 1
        print(f"\n  Decrypted response:\n  {response.decode('utf-8')}")
    except Exception as e:
        print(f"\n  *** REJECTED: {e} ***")

print("\nDone.")
