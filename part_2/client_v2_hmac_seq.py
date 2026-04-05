# client_v2_hmac_seq.py
#
# PART 2 — HMAC + SEQUENCE NUMBERS CLIENT (STAGE 2)
#
# WHAT THIS FILE DOES:
#   A TCP client that protects messages with AES-CTR + HMAC-SHA256 and
#   includes sequence numbers in the HMAC input.  This is the middle step
#   between the basic HMAC client (Stage 1) and the AEAD client (Stage 3).
#
# WHAT IS NEW RELATIVE TO client_v2_hmac.py (STAGE 1):
#   - Maintains send_seq and recv_seq counters.
#   - Each record carries an 8-byte sequence number on the wire.
#   - The HMAC now covers seq || nonce || ciphertext, so replayed or
#     reordered records are detected even if their individual MACs are valid.
#
# WHY THIS MATTERS:
#   In Stage 1, each record was authenticated in isolation.  An attacker
#   could replay record #0 in the slot where record #5 is expected and
#   the receiver would accept it — the HMAC still matches.  Sequence
#   numbers bind each record to its position in the stream and close
#   that gap.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_hmac_seq.py
#   Terminal 2:  python client_v2_hmac_seq.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared keys, no handshake.
#   - Encryption and MAC are still separate primitives (Stage 3 unifies them).
#   - Single request-response, then done.

import socket

from framing import send_record, recv_record
from crypto_hmac_seq import protect_record, verify_and_unprotect

HOST = "127.0.0.1"
PORT = 9003

# Sequence counters — sender and receiver each maintain their own.
# The sender increments after each record sent.
# The receiver expects consecutive values starting from 0.
send_seq = 0
recv_seq = 0

# A toy HTTP-like request — same spirit as Part 1.
request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")

print("=" * 60)
print("Part 2 — HMAC + Sequence Numbers Client (Stage 2)")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # ----- SEND REQUEST -----
    print(f"\n--- Sending request (send_seq={send_seq}) ---")
    protected = protect_record(send_seq, request)
    send_record(client, protected)
    send_seq += 1
    print(f"  Record sent ({len(protected)} bytes on wire)")

    # ----- RECEIVE RESPONSE -----
    print(f"\n--- Receiving response (expecting recv_seq={recv_seq}) ---")
    raw_response = recv_record(client)

    try:
        response = verify_and_unprotect(recv_seq, raw_response)
        recv_seq += 1
        print(f"\n  Decrypted response:\n  {response.decode('utf-8')}")
    except ValueError as e:
        print(f"\n  *** REJECTED: {e} ***")

print("\nDone.")
