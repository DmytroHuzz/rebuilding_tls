# server_v2.py
#
# PART 3, VERSION 2 — X25519 SERVER
#
# WHAT THIS FILE DOES:
#   Accepts one connection, performs an X25519 key exchange, and
#   demonstrates that both sides arrive at the same 32-byte shared secret.
#
# WHAT CHANGED FROM v1 (CLASSIC DH):
#   - No prime/generator parameters to manage.
#   - Compact 32-byte public keys.
#   - The `cryptography` library handles all curve arithmetic internally.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication — MITM still possible.
#   - Shared secret is not used for anything yet.
#   - Accepts one connection, then exits.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2.py
#   Terminal 2:  python client_v2.py

import socket
from handshake import server_handshake

HOST = "127.0.0.1"
PORT = 10002

print("=" * 60)
print("Part 3, v2 — X25519 Server")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # Perform the X25519 handshake.
        shared_secret = server_handshake(conn)

        print("=" * 60)
        print(f"  Shared secret (server): {shared_secret.hex()}")
        print(f"  Length: {len(shared_secret)} bytes")
        print()
        print("  Compare with the client — they should match.")
        print()
        print("  This X25519 handshake is what TLS 1.3 uses (along with")
        print("  certificates for authentication, which we don't have yet).")
        print("=" * 60)

print("\nDone.")
