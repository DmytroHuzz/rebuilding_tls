# client_v2_hmac.py
#
# PART 2 — HMAC CLIENT (STAGE 1)
#
# WHAT THIS FILE DOES:
#   A simple TCP client that protects its messages with AES-CTR encryption
#   + HMAC-SHA256, using the encrypt-then-MAC construction from crypto_hmac.py.
#
# WHAT IS NEW RELATIVE TO PART 1:
#   In Part 1 (client_v1.py), we only encrypted.  An attacker could modify
#   ciphertext bits undetected.  Now every record carries an HMAC tag, so
#   the server can detect any tampering.
#
# HOW TO RUN:
#   Terminal 1:  python server_v2_hmac.py
#   Terminal 2:  python client_v2_hmac.py
#
# WHAT IS STILL SIMPLIFIED:
#   - Pre-shared keys, no handshake.
#   - No sequence numbers in this version (see client_v2_hmac_seq.py for that).
#   - Single request-response, then done.

import socket

from framing import send_record, recv_record
from crypto_hmac import encrypt_then_mac, verify_then_decrypt

HOST = "127.0.0.1"
PORT = 9001

# A toy HTTP-like request — same spirit as Part 1.
request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")

print("=" * 60)
print("Part 2 — HMAC Client (encrypt-then-MAC)")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # ----- SEND REQUEST -----
    print("\n--- Sending request ---")
    protected = encrypt_then_mac(request)
    send_record(client, protected)
    print(f"  Record sent ({len(protected)} bytes on wire)")

    # ----- RECEIVE RESPONSE -----
    print("\n--- Receiving response ---")
    raw_response = recv_record(client)
    response = verify_then_decrypt(raw_response)
    print(f"\n  Decrypted response:\n  {response.decode('utf-8')}")

print("\nDone.")
