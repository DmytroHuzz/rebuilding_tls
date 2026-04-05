# server_v2_hmac_seq.py
#
# PART 2 — HMAC + SEQUENCE NUMBERS SERVER (STAGE 2)
#
# WHAT THIS FILE DOES:
#   A TCP server that protects messages with AES-CTR + HMAC-SHA256 and
#   verifies both the MAC and the sequence number before decrypting.
#   This is the middle step between the basic HMAC server (Stage 1) and
#   the AEAD server (Stage 3).
#
# WHAT IS NEW RELATIVE TO server_v2_hmac.py (STAGE 1):
#   - Maintains send_seq and recv_seq counters.
#   - Each record carries an 8-byte sequence number.
#   - The HMAC covers seq || nonce || ciphertext, so:
#       • replaying an old record fails (wrong sequence number)
#       • reordering records fails (sequence mismatch)
#       • dropping a record causes all subsequent records to fail
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_hmac_seq.py
#   Terminal 2:  python client_v2_hmac_seq.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared keys, no handshake.
#   - Encryption and MAC are still separate primitives (Stage 3 unifies them).
#   - Accepts one connection, then exits.

import socket

from framing import send_record, recv_record
from crypto_hmac_seq import protect_record, verify_and_unprotect

HOST = "127.0.0.1"
PORT = 9003

# Sequence counters.
# The server's recv_seq tracks the client's send_seq, and vice versa.
send_seq = 0
recv_seq = 0

print("=" * 60)
print("Part 2 — HMAC + Sequence Numbers Server (Stage 2)")
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
            request = verify_and_unprotect(recv_seq, raw_request)
            recv_seq += 1
        except ValueError as e:
            # Rejection: either the MAC is invalid, the sequence number
            # is wrong, or the data was tampered with / replayed.
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

            protected = protect_record(send_seq, response)
            send_record(conn, protected)
            send_seq += 1
            print(f"  Record sent ({len(protected)} bytes on wire)")

print("\nDone.")
