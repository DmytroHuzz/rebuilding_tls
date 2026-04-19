# client_v3.py
#
# PART 3, VERSION 3 — HKDF SESSION KEYS CLIENT
#
# WHAT THIS FILE DOES:
#   Connects to the server, performs an X25519 + HKDF handshake to
#   establish fresh session keys, then exchanges application data
#   protected by AES-GCM (AEAD) — using the derived keys, NOT a
#   hardcoded pre-shared key.
#
# THE FULL ARCHITECTURE (visible in this version):
#
#   handshake → shared secret → HKDF → session keys → AEAD records
#
#   This is the pipeline that Part 3 has been building toward.
#
# WHAT CHANGED FROM PART 2:
#   In Part 2, the AEAD key was:
#     AEAD_KEY = b"AEAD_KEY_PART2_DEMO_FOR_AES_GCM!"   # hardcoded
#
#   In Part 3 v3, the AEAD keys are derived dynamically:
#     client_write_key, server_write_key = derive_session_keys(shared_secret)
#
#   The record format on the wire is the SAME as Part 2 Stage 3:
#     seq (8 B) || nonce (12 B) || ciphertext_and_tag (N+16 B)
#
#   But the keys are fresh for every session — no more pre-shared secrets.
#
# KEY USAGE:
#   - Client encrypts with client_write_key (server decrypts with same key)
#   - Client decrypts server's messages with server_write_key
#   - This directional key separation prevents nonce-reuse issues
#
# WHAT IS STILL SIMPLIFIED:
#   - This is still not real TLS because the handshake is not authenticated.
#   - A man-in-the-middle can intercept and substitute public keys.
#   - No certificates, no trust chain, no identity verification.
#
# HOW TO RUN:
#   Terminal 1:  python server_v3.py
#   Terminal 2:  python client_v3.py

import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

from framing import send_record, recv_record
from handshake import client_handshake
from record_protection import protect_record, unprotect_record

HOST = "127.0.0.1"
PORT = 10003

# Sequence counters — same concept as Part 2.
send_seq = 0
recv_seq = 0

# A toy HTTP-like request — same spirit as Part 1 and Part 2.
request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")

print("=" * 60)
print("Part 3, v3 — HKDF Session Keys Client")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # ==========================================
    # PHASE 1: HANDSHAKE
    # ==========================================
    # New in Part 3: the handshake dynamically establishes session keys.
    # No pre-shared secret needed.
    client_write_key, server_write_key = client_handshake(client)

    # ==========================================
    # PHASE 2: APPLICATION DATA
    # ==========================================
    # The record layer now uses HKDF-derived keys instead of hardcoded ones.
    # The record format is the same as Part 2 Stage 3 (AEAD).

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
