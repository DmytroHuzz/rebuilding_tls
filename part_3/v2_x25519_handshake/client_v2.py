# client_v2.py
#
# PART 3, VERSION 2 — X25519 CLIENT
#
# WHAT THIS FILE DOES:
#   Connects to the server, performs an X25519 key exchange, and
#   demonstrates that both sides arrive at the same 32-byte shared secret.
#
# WHAT CHANGED FROM v1 (CLASSIC DH):
#   - No big prime or generator — X25519 uses a fixed standard curve.
#   - Keypairs are just 32 bytes — much more compact than the 256-byte
#     public values in classic 2048-bit DH.
#   - The handshake code is simpler: generate(), exchange(), done.
#
# WHAT IS STILL SIMPLIFIED:
#   - No authentication — MITM still possible.
#   - Shared secret is not yet turned into session keys.
#   - No record-layer encryption.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2.py
#   Terminal 2:  python client_v2.py

import socket
from handshake import client_handshake

HOST = "127.0.0.1"
PORT = 10002

print("=" * 60)
print("Part 3, v2 — X25519 Client")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # Perform the X25519 handshake.
    shared_secret = client_handshake(client)

    print("=" * 60)
    print(f"  Shared secret (client): {shared_secret.hex()}")
    print(f"  Length: {len(shared_secret)} bytes")
    print()
    print("  Compare with the server — they should match.")
    print()
    print("  Notice how much simpler this is compared to v1.")
    print("  No giant prime, no generator, no modular exponentiation.")
    print("  Just 32-byte public keys and one call to exchange().")
    print()
    print("  Next step (v3): derive actual session keys with HKDF")
    print("  and protect application data with AEAD.")
    print("=" * 60)

print("\nDone.")
