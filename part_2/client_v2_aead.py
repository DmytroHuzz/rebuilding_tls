# client_v2_aead.py
#
# PART 2 — AEAD CLIENT (STAGE 3)
#
# WHAT THIS FILE DOES:
#   A TCP client that protects messages with AES-GCM (AEAD).
#   This is the most advanced version in Part 2.
#
# WHAT IS NEW RELATIVE TO THE HMAC CLIENT:
#   - Uses AES-GCM instead of separate AES-CTR + HMAC-SHA256.
#   - Confidentiality and integrity are handled by a single primitive.
#   - Maintains send/receive sequence counters for record ordering.
#   - This AEAD version is closer to real-world protocols because
#     confidentiality and integrity are combined in one primitive.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_aead.py
#   Terminal 2:  python client_v2_aead.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared key, no handshake, no key exchange.
#   - No peer identity or trust model.
#   - This is still not real TLS because both sides still start with
#     pre-shared key material.

import socket

from framing import send_record, recv_record
from crypto_aead import protect_record_aead, unprotect_record_aead

HOST = "127.0.0.1"
PORT = 9002

# Sequence counters — sender and receiver each maintain their own.
# The sender increments after each record sent.
# The receiver expects consecutive values starting from 0.
send_seq = 0
recv_seq = 0

# A toy HTTP-like request.
request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")

print("=" * 60)
print("Part 2 — AEAD Client (AES-GCM)")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # ----- SEND REQUEST -----
    print(f"\n--- Sending request (send_seq={send_seq}) ---")
    protected = protect_record_aead(send_seq, request)
    send_record(client, protected)
    send_seq += 1
    print(f"  Record sent ({len(protected)} bytes on wire)")

    # ----- RECEIVE RESPONSE -----
    print(f"\n--- Receiving response (expecting recv_seq={recv_seq}) ---")
    raw_response = recv_record(client)

    try:
        response = unprotect_record_aead(recv_seq, raw_response)
        recv_seq += 1
        print(f"\n  Decrypted response:\n  {response.decode('utf-8')}")
    except Exception as e:
        print(f"\n  *** REJECTED: {e} ***")

print("\nDone.")
