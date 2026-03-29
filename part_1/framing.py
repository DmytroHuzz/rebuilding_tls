# framing.py
#
# WHY THIS FILE EXISTS:
#   TCP is a *stream* protocol — it delivers raw bytes with NO concept
#   of "messages".  If you send 50 bytes and then 50 bytes, the receiver
#   might get one 100-byte chunk, or five 20-byte chunks, or anything else.
#
#   To know where one message ends and the next begins, we use a simple
#   trick called LENGTH-PREFIXING:
#
#     +-------------------+---------------------+
#     | length (4 bytes)  |  payload (N bytes)   |
#     +-------------------+---------------------+
#
#   The sender writes the payload size first, then the payload itself.
#   The receiver reads 4 bytes to learn the size, then reads exactly
#   that many bytes.  Problem solved.

import struct
# `struct` is a Python standard library module for converting between
# Python values and C-style binary data (raw bytes).  We use it to
# encode/decode the 4-byte length prefix.


def send_record(sock, payload: bytes) -> None:
    """Send one complete message (record) over a TCP socket."""

    # struct.pack(format, value) converts a Python integer into raw bytes.
    #
    #   "!I" is the format string:
    #     "!" = network byte order (big-endian: most significant byte first).
    #           This is the standard for network protocols — both sides
    #           agree on byte order regardless of CPU architecture.
    #     "I" = unsigned 32-bit integer (4 bytes, range 0 .. 4,294,967,295).
    #
    # So struct.pack("!I", 13) produces b'\x00\x00\x00\x0d' — the number 13
    # encoded as 4 bytes in big-endian order.
    #
    # We pack len(payload) so the receiver knows how many bytes to expect.
    header = struct.pack("!I", len(payload))

    # sock.sendall() sends ALL the bytes — unlike sock.send(), which may
    # send only a partial chunk.  sendall() loops internally until every
    # byte is delivered to the OS network buffer.
    sock.sendall(header + payload)


def recv_exact(sock, n: int) -> bytes:
    """Receive exactly `n` bytes from a socket.

    Why not just call sock.recv(n)?
      Because recv() may return FEWER bytes than requested — it returns
      whatever the OS has buffered so far.  For example, recv(1000) might
      return only 200 bytes if that's all that has arrived.

      So we loop, collecting chunks until we have all `n` bytes.
    """
    chunks = []
    remaining = n

    while remaining > 0:
        # Ask for up to `remaining` bytes.  May get fewer.
        chunk = sock.recv(remaining)
        if not chunk:
            # recv() returns b"" (empty bytes) when the peer has closed
            # the connection.  If we still need data, that's an error.
            raise ConnectionError("Connection closed while reading data")
        chunks.append(chunk)
        remaining -= len(chunk)

    # Join all collected chunks into a single bytes object.
    return b"".join(chunks)


def recv_record(sock) -> bytes:
    """Receive one complete message (record) from a TCP socket."""

    # Step 1: Read the 4-byte length header.
    header = recv_exact(sock, 4)

    # Step 2: Unpack the header back into a Python integer.
    #
    #   struct.unpack("!I", header) returns a TUPLE — even for a single
    #   value.  The syntax (length,) = ... unpacks that one-element tuple
    #   into the variable `length`.
    #
    #   Example: header = b'\x00\x00\x00\x0d'
    #            struct.unpack("!I", header) → (13,)
    #            (length,) = (13,)  →  length = 13
    (length,) = struct.unpack("!I", header)

    # Step 3: Read exactly `length` bytes — the actual payload.
    return recv_exact(sock, length)
