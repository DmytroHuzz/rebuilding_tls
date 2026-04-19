# key_schedule.py
#
# KEY SCHEDULE — HKDF-based key derivation from the handshake shared secret.
#
# WHAT THIS FILE DOES:
#   Takes the raw 32-byte shared secret from the X25519 handshake and
#   derives actual session keys for the AEAD record layer.
#
# WHY A KDF IS NEEDED:
#   The raw shared secret from X25519 should NOT be used directly as an
#   encryption key.  Here is why:
#
#   1. KEY SEPARATION.  We want separate keys for client→server and
#      server→client traffic.  Using the same key in both directions is
#      dangerous: if the same nonce is ever reused, security breaks.
#      Deriving two directional keys from one shared secret eliminates
#      this risk.
#
#   2. UNIFORM KEY MATERIAL.  The X25519 output, while high-entropy, has
#      a specific algebraic structure (it is a point coordinate on an
#      elliptic curve).  A KDF produces output that is indistinguishable
#      from random bytes — better suited as key material for AES-GCM.
#
#   3. CLEANER PROTOCOL STRUCTURE.  In real TLS 1.3, HKDF is used
#      throughout the key schedule: for the handshake keys, the
#      application keys, the resumption secret, etc.  We are building
#      toward that same structure.
#
# WHAT IS HKDF:
#   HKDF (HMAC-based Key Derivation Function, RFC 5869) has two steps:
#
#     1. EXTRACT — compress the input key material into a fixed-length
#        pseudorandom key (PRK).  This is done with HMAC.
#        PRK = HMAC-SHA256(salt, input_key_material)
#
#     2. EXPAND — expand the PRK into as many bytes of output key material
#        as needed, using different "info" strings to derive independent keys.
#        OKM = HKDF-Expand(PRK, info, length)
#
#   By using different "info" labels, we derive independent keys from the
#   same shared secret.
#
# WHAT WE DERIVE:
#   - client_write_key (32 bytes) — used by client to encrypt, server to decrypt
#   - server_write_key (32 bytes) — used by server to encrypt, client to decrypt
#
# WHAT IS NEW IN PART 3:
#   Everything.  Part 2 used hardcoded keys.  Part 3 derives fresh session
#   keys from the handshake shared secret using HKDF.
#
# WHAT IS STILL SIMPLIFIED:
#   - We use a static empty salt.  Real TLS 1.3 uses a more complex salt
#     derived from earlier handshake stages.
#   - We only derive two keys.  Real TLS derives additional secrets for
#     resumption, exporters, etc.
#   - No transcript hash.  Real TLS includes a hash of the handshake
#     transcript in the key derivation to bind keys to the exact handshake.

from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes


# The "info" labels used in HKDF-Expand to derive independent keys.
# Different labels produce different, cryptographically independent keys
# from the same PRK.
CLIENT_WRITE_KEY_LABEL = b"part3 client write key"
SERVER_WRITE_KEY_LABEL = b"part3 server write key"

# Key length for AES-256-GCM.
KEY_LEN = 32


def derive_session_keys(shared_secret: bytes) -> tuple:
    """Derive client_write_key and server_write_key from the shared secret.

    Uses HKDF-SHA256 with separate info labels for key separation.

    Args:
        shared_secret: The raw 32-byte X25519 shared secret.

    Returns:
        (client_write_key, server_write_key) — each 32 bytes.
    """
    # Step 1: Derive client_write_key.
    # HKDF turns the raw shared secret into actual session keys.
    # The "info" label ensures this output is cryptographically independent
    # from the server_write_key, even though they come from the same secret.
    client_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,  # None → HKDF uses a zero-filled salt internally
        info=CLIENT_WRITE_KEY_LABEL,
    ).derive(shared_secret)

    # Step 2: Derive server_write_key with a different info label.
    server_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=SERVER_WRITE_KEY_LABEL,
    ).derive(shared_secret)

    print(f"  [key_schedule] Derived session keys from shared secret:")
    print(f"    client_write_key = {client_write_key.hex()[:32]}...")
    print(f"    server_write_key = {server_write_key.hex()[:32]}...")

    return client_write_key, server_write_key
