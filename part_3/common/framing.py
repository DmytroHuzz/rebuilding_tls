# framing.py
#
# TRANSPORT FRAMING — length-prefixed records over TCP.
#
# WHY THIS FILE EXISTS:
#   TCP is a *stream* protocol — bytes arrive with no message boundaries.
#   We add a 4-byte length prefix so the receiver knows where one record
#   ends and the next begins.
#
# WHAT IS NEW IN PART 3:
#   Nothing.  The framing layer is unchanged from Part 1 and Part 2.
#   Framing is a transport concern.  Part 3 changes what goes INSIDE the
#   payload (handshake messages, derived-key AEAD records), but the way we
#   delimit records on the wire stays the same.
#
# RECORD FORMAT ON THE WIRE:
#
#     +-------------------+---------------------+
#     | length (4 bytes)  |  payload (N bytes)   |
#     +-------------------+---------------------+
#       big-endian uint32    opaque to framing

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
