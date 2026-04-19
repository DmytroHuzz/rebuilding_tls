# handshake_messages.py
#
# HANDSHAKE MESSAGE ENCODING — simple tag-length-value helpers.
#
# WHY THIS FILE EXISTS:
#   During the handshake, client and server need to exchange structured
#   data: public keys, parameters, etc.  We need a simple way to pack
#   and unpack these values into bytes for transmission over the socket.
#
#   We use a trivially simple approach: every handshake field is sent as
#   a 2-byte tag + 2-byte length + raw value.  This is NOT the real TLS
#   handshake encoding (which uses a much richer structure), but it is
#   easy to read, easy to debug, and sufficient for learning.
#
# WHAT IS NEW IN PART 3:
#   This file did not exist in Part 2.  Part 2 had no handshake at all —
#   keys were hardcoded.  Part 3 introduces a handshake, so we need a
#   minimal encoding for handshake fields.
#
# IMPORTANT:
#   This is NOT ASN.1, NOT TLS record layer encoding.  It is a toy format
#   designed for clarity.

import struct


# ---------------------------------------------------------------------------
# Tags — identify what each field contains.
# These are arbitrary 2-byte identifiers, chosen for readability.
# ---------------------------------------------------------------------------
TAG_DH_P = 0x0001  # Classic DH: the prime p
TAG_DH_G = 0x0002  # Classic DH: the generator g
TAG_DH_PUBLIC = 0x0003  # Classic DH: a public value (g^a mod p)
TAG_X25519_PUBLIC = 0x0010  # X25519: a 32-byte public key
TAG_HANDSHAKE_DONE = 0x00FF  # Signals handshake is complete


def encode_field(tag: int, value: bytes) -> bytes:
    """Encode one handshake field as tag (2 B) || length (2 B) || value.

    This is a minimal TLV (tag-length-value) encoding.
    """
    return struct.pack("!HH", tag, len(value)) + value


def decode_field(data: bytes, offset: int = 0) -> tuple:
    """Decode one handshake field starting at `offset`.

    Returns (tag, value, new_offset).
    """
    if len(data) < offset + 4:
        raise ValueError("Not enough data for field header")
    tag, length = struct.unpack("!HH", data[offset : offset + 4])
    value = data[offset + 4 : offset + 4 + length]
    if len(value) < length:
        raise ValueError(f"Field truncated: expected {length} bytes, got {len(value)}")
    return tag, value, offset + 4 + length


def encode_message(fields: list) -> bytes:
    """Encode a list of (tag, value_bytes) pairs into a single message."""
    parts = []
    for tag, value in fields:
        parts.append(encode_field(tag, value))
    return b"".join(parts)


def decode_message(data: bytes) -> list:
    """Decode a message into a list of (tag, value_bytes) pairs."""
    fields = []
    offset = 0
    while offset < len(data):
        tag, value, offset = decode_field(data, offset)
        fields.append((tag, value))
    return fields
