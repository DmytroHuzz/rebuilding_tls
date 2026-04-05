# server_v2_hmac.py
#
# PART 2 — HMAC SERVER (STAGE 1)
#
# WHAT THIS FILE DOES:
#   A simple TCP server that protects its responses with AES-CTR encryption
#   + HMAC-SHA256.  It verifies incoming records before decrypting them.
#
# WHAT IS NEW RELATIVE TO PART 1:
#   In Part 1 (server_v1.py), the server decrypted blindly — there was no
#   way to tell if the ciphertext had been modified in transit.  Now the
#   server checks the HMAC tag first.  If the tag does not match, the
#   record is rejected and never decrypted.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_hmac.py
#   Terminal 2:  python client_v2_hmac.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared keys, no handshake.
#   - No sequence numbers (see server_v2_hmac_seq.py for that).
#   - Accepts a single connection, then exits.

import socket

from framing import send_record, recv_record
from crypto_hmac import encrypt_then_mac, verify_then_decrypt

HOST = "127.0.0.1"
PORT = 9001

print("=" * 60)
print("Part 2 — HMAC Server (encrypt-then-MAC)")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    # SO_REUSEADDR lets us restart the server immediately without waiting
    # for the OS to release the port from TIME_WAIT state.
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # ----- RECEIVE REQUEST -----
        print("\n--- Receiving request ---")
        raw_request = recv_record(conn)

        try:
            request = verify_then_decrypt(raw_request)
        except ValueError as e:
            # New in Part 2: if the MAC fails, we reject the record loudly.
            # In Part 1 we had no way to detect tampering at all.
            print(f"\n  *** REJECTED: {e} ***")
            print("  Connection closed — refusing to process tampered data.")
        else:
            print(f"\n  Decrypted request:\n  {request.decode('utf-8')}")

            # ----- SEND RESPONSE -----
            print("--- Sending response ---")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n\r\n"
                "hello, client"
            ).encode("utf-8")

            protected = encrypt_then_mac(response)
            send_record(conn, protected)
            print(f"  Record sent ({len(protected)} bytes on wire)")

print("\nDone.")
