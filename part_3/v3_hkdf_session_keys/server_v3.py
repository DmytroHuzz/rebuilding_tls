# server_v3.py
#
# PART 3, VERSION 3 — HKDF SESSION KEYS SERVER
#
# WHAT THIS FILE DOES:
#   Accepts one connection, performs an X25519 + HKDF handshake to
#   establish fresh session keys, then exchanges application data
#   protected by AES-GCM (AEAD) with the derived keys.
#
# KEY USAGE:
#   - Server decrypts client's messages with client_write_key
#   - Server encrypts its responses with server_write_key
#   - These keys are fresh for every session
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication — MITM still possible (see mitm_explainer.md).
#   - No certificates, no trust chain.
#   - Accepts one connection, then exits.
#
# HOW TO RUN:
#   Terminal 1:  python server_v3.py
#   Terminal 2:  python client_v3.py

import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

from framing import send_record, recv_record
from handshake import server_handshake
from record_protection import protect_record, unprotect_record

HOST = "127.0.0.1"
PORT = 10003

# Sequence counters.
send_seq = 0
recv_seq = 0

print("=" * 60)
print("Part 3, v3 — HKDF Session Keys Server")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # ==========================================
        # PHASE 1: HANDSHAKE
        # ==========================================
        client_write_key, server_write_key = server_handshake(conn)

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
