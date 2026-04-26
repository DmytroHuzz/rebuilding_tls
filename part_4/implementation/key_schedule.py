# key_schedule.py
#
# KEY SCHEDULE — HKDF-based key derivation (carried forward from Part 3 v3).
#
# WHAT THIS FILE DOES:
#   Takes the raw 32-byte shared secret from the X25519 handshake and
#   derives session keys for the AEAD record layer using HKDF.
#
# WHAT IS NEW IN PART 4:
#   Nothing in the key schedule itself.  The derivation logic is unchanged.
#   What changed is *how* the shared secret is established: in Part 3 the
#   handshake was unauthenticated, so a MITM could substitute public keys.
#   Part 4 adds certificate authentication to the handshake, ensuring
#   the client is deriving keys with the real server.

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CLIENT_WRITE_KEY_LABEL = b"part4 client write key"
SERVER_WRITE_KEY_LABEL = b"part4 server write key"

KEY_LEN = 32  # AES-256-GCM


def derive_session_keys(shared_secret: bytes) -> tuple:
    """Derive (client_write_key, server_write_key) from the shared secret."""
    client_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=CLIENT_WRITE_KEY_LABEL,
    ).derive(shared_secret)

    server_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=SERVER_WRITE_KEY_LABEL,
    ).derive(shared_secret)

    print(f"  [key_schedule] Derived session keys:")
    print(f"    client_write_key = {client_write_key.hex()[:32]}...")
    print(f"    server_write_key = {server_write_key.hex()[:32]}...")

    return client_write_key, server_write_key
