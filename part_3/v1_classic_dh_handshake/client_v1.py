# client_v1.py
#
# PART 3, VERSION 1 — CLASSIC DH CLIENT
#
# WHAT THIS FILE DOES:
#   Connects to the server, performs a classic Diffie-Hellman handshake,
#   and demonstrates that both sides arrive at the same shared secret.
#
# WHAT IS NEW IN PART 3:
#   New in Part 3: we no longer assume a pre-shared application key.
#   Instead, the client and server dynamically establish a shared secret
#   through a Diffie-Hellman key exchange.
#
# PURPOSE OF THIS VERSION:
#   This classic DH version exists to make the shared-secret idea visible
#   before switching to the cleaner X25519 workflow in v2.  The math here
#   (g^a mod p) is the textbook construction.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication — vulnerable to man-in-the-middle attack.
#   - The shared secret is not yet used for record-layer encryption.
#   - No derived session keys (that comes in v3).
#
# HOW TO RUN:
#   Terminal 1:  python server_v1.py
#   Terminal 2:  python client_v1.py

import socket
from handshake import client_handshake

HOST = "127.0.0.1"
PORT = 8080

print("=" * 60)
print("Part 3, v1 — Classic Diffie-Hellman Client")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # Perform the classic DH handshake.
    shared_secret = client_handshake(client)

    # At this point both sides have the same shared secret.
    # In v1 we just print it to prove the math works.
    # In v3 we will derive actual session keys from it.
    print("=" * 60)
    print(f"  Shared secret (client): {shared_secret.hex()[:64]}...")
    print(f"  Length: {len(shared_secret)} bytes")
    print()
    print("  Both sides should show the same shared secret.")
    print("  This proves the Diffie-Hellman key exchange works.")
    print()
    print("  NOTE: We are not encrypting application data yet.")
    print("  That comes in v3 (HKDF + AEAD record layer).")
    print("=" * 60)

print("\nDone.")
