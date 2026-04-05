# server_v2_aead.py
#
# PART 2 — AEAD SERVER (STAGE 3)
#
# WHAT THIS FILE DOES:
#   A TCP server that protects messages with AES-GCM (AEAD).
#   This is the most advanced version in Part 2 — it replaces the manual
#   AES-CTR + HMAC construction with a single AEAD primitive.
#
# WHAT IS NEW RELATIVE TO THE HMAC SERVER:
#   - Uses AES-GCM instead of separate AES-CTR + HMAC-SHA256.
#   - Maintains send/receive sequence counters.
#   - If the AEAD tag or sequence number is wrong, the record is rejected.
#   - No separate "verify then decrypt" step — AEAD does both atomically.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_aead.py
#   Terminal 2:  python client_v2_aead.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared key, no handshake, no key exchange.
#   - No peer identity or trust model.
#   - Accepts one connection, then exits.

import socket

from framing import send_record, recv_record
from crypto_aead import protect_record_aead, unprotect_record_aead

HOST = "127.0.0.1"
PORT = 9002

# Sequence counters.
# The server's recv_seq tracks the client's send_seq, and vice versa.
send_seq = 0
recv_seq = 0

print("=" * 60)
print("Part 2 — AEAD Server (AES-GCM)")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # ----- RECEIVE REQUEST -----
        print(f"\n--- Receiving request (expecting recv_seq={recv_seq}) ---")
        raw_request = recv_record(conn)

        try:
            request = unprotect_record_aead(recv_seq, raw_request)
            recv_seq += 1
        except Exception as e:
            # AEAD rejection: either the auth tag is invalid, the sequence
            # number is wrong, or the data was tampered with.
            print(f"\n  *** REJECTED: {e} ***")
            print("  Connection closed — refusing to process invalid data.")
        else:
            print(f"\n  Decrypted request:\n  {request.decode('utf-8')}")

            # ----- SEND RESPONSE -----
            print(f"--- Sending response (send_seq={send_seq}) ---")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n\r\n"
                "hello, client"
            ).encode("utf-8")

            protected = protect_record_aead(send_seq, response)
            send_record(conn, protected)
            send_seq += 1
            print(f"  Record sent ({len(protected)} bytes on wire)")

print("\nDone.")
