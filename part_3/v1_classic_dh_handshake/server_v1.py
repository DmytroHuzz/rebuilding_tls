# server_v1.py
#
# PART 3, VERSION 1 — CLASSIC DH SERVER
#
# WHAT THIS FILE DOES:
#   Accepts one connection, performs a classic Diffie-Hellman handshake,
#   and demonstrates that both sides arrive at the same shared secret.
#
# WHAT IS NEW IN PART 3:
#   New in Part 3: we no longer assume a pre-shared application key.
#   The server dynamically establishes a shared secret with the client
#   through a Diffie-Hellman key exchange.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication — a man-in-the-middle can impersonate either side.
#   - The shared secret is not used for anything yet.
#   - Accepts one connection, then exits.
#
# HOW TO RUN:
#   Terminal 1:  python server_v1.py
#   Terminal 2:  python client_v1.py

import socket
from handshake import server_handshake

HOST = "127.0.0.1"
PORT = 8080

print("=" * 60)
print("Part 3, v1 — Classic Diffie-Hellman Server")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # Perform the classic DH handshake.
        shared_secret = server_handshake(conn)

        # Print the result so we can compare with the client.
        print("=" * 60)
        print(f"  Shared secret (server): {shared_secret.hex()[:64]}...")
        print(f"  Length: {len(shared_secret)} bytes")
        print()
        print("  Both sides should show the same shared secret.")
        print("  This proves the Diffie-Hellman key exchange works.")
        print()
        print("  NOTE: We are not encrypting application data yet.")
        print("  That comes in v3 (HKDF + AEAD record layer).")
        print("=" * 60)

print("\nDone.")
