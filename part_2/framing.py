# framing.py
#
# TRANSPORT FRAMING — length-prefixed records over TCP.
#
# WHY THIS FILE EXISTS:
#   TCP is a *stream* protocol — it delivers raw bytes with no concept of
#   message boundaries.  We use a simple 4-byte length prefix so the
#   receiver knows where one record ends and the next begins.
#
# WHAT IS NEW IN PART 2:
#   Nothing.  The framing layer is intentionally unchanged from Part 1.
#   Framing is a transport concern, not a cryptographic one.  Part 2
#   adds integrity (HMAC) and authenticated encryption (AEAD) — those
#   happen INSIDE the payload, not at the framing level.
#
# RECORD FORMAT ON THE WIRE:
#
#     +-------------------+---------------------+
#     | length (4 bytes)  |  payload (N bytes)   |
#     +-------------------+---------------------+
#       big-endian uint32    opaque to framing
#
#   The framing layer treats the payload as opaque bytes.
#   It does not know or care whether the payload is plaintext,
#   ciphertext, or ciphertext-with-a-MAC.

import struct


def send_record(sock, payload: bytes) -> None:
    """Send one length-prefixed record over a TCP socket."""
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_exact(sock, n: int) -> bytes:
    """Read exactly `n` bytes from a socket, looping if necessary."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_record(sock) -> bytes:
    """Receive one complete length-prefixed record from a TCP socket."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    return recv_exact(sock, length)
