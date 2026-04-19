# dh_math.py
#
# CLASSIC DIFFIE-HELLMAN — the raw math.
#
# WHAT THIS FILE DOES:
#   Implements the core Diffie-Hellman key-agreement math using standard
#   Python integers.  This is the textbook version:
#
#     public_value = g^private mod p
#     shared_secret = peer_public^private mod p
#
#   Both sides independently arrive at the same shared secret without
#   ever transmitting their private exponents.
#
# WHY THIS VERSION EXISTS:
#   This classic DH version exists to make the shared-secret idea visible
#   before switching to the cleaner X25519 workflow in v2.  Real-world
#   protocols use curves like X25519, not raw modular exponentiation with
#   huge primes.  But the underlying idea — "exchange public values,
#   independently compute the same secret" — is the same.
#
# WHAT IS NEW IN PART 3:
#   Everything.  Part 2 had no key exchange at all — both sides used
#   hardcoded keys.  Part 3 introduces a handshake so the shared secret
#   is established dynamically.
#
# WHAT IS STILL SIMPLIFIED:
#   - We use a hardcoded 2048-bit prime and generator for the demo.
#     In a real protocol you would use well-known standardized groups
#     (RFC 3526 / RFC 7919) or negotiate parameters.
#   - No parameter validation beyond basic sanity checks.
#   - This is NOT the version we want to keep — v2 (X25519) is cleaner.

import os

# ---------------------------------------------------------------------------
# PUBLIC PARAMETERS — shared between client and server.
#
# In classic Diffie-Hellman, both sides must agree on:
#   p — a large prime number
#   g — a generator (base) for the multiplicative group mod p
#
# These parameters do NOT need to be secret.  They can be sent over the
# wire in the clear, or (as we do here) hardcoded as well-known values.
#
# We use a 2048-bit MODP group from RFC 3526, Group 14.  This is a
# standard, well-vetted set of parameters used widely in practice.
# ---------------------------------------------------------------------------

# RFC 3526 Group 14: 2048-bit MODP prime
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# Generator for the group.  g=2 is standard for RFC 3526 groups.
DH_GENERATOR = 2


def generate_private_exponent() -> int:
    """Generate a random private exponent.

    The private exponent must be a random number in [2, p-2].
    We generate 256 random bits, which is more than enough entropy
    for this 2048-bit group.

    The private exponent is the ONE thing that never leaves each side.
    It is never sent over the wire.  Everything else — p, g, and the
    public value — is public.
    """
    # 32 bytes = 256 bits of randomness.
    return int.from_bytes(os.urandom(32), "big")


def compute_public_value(private: int, g: int, p: int) -> int:
    """Compute the public value: g^private mod p.

    Args:
        private: The secret exponent (never sent over the wire).
        g:       The generator / base (public, sent in the ClientHello).
        p:       The prime modulus (public, sent in the ClientHello).

    Returns:
        The public DH value that you send to the peer.

    The peer cannot recover your private exponent from this value
    (that would require solving the discrete logarithm problem,
    which is computationally infeasible for large primes).
    """
    # Python's built-in pow(base, exp, mod) does modular exponentiation
    # efficiently using fast exponentiation (square-and-multiply).
    return pow(g, private, p)


def compute_shared_secret(peer_public: int, private: int, p: int) -> int:
    """Compute the shared secret: peer_public^private mod p.

    Args:
        peer_public: The other side's public value (received over the wire).
        private:     Our secret exponent (never sent).
        p:           The prime modulus (agreed upon during the handshake).

    Both sides compute this independently:
      - client computes: server_public^client_private mod p
      - server computes: client_public^server_private mod p

    These are equal because:
      (g^b)^a mod p = g^(ab) mod p = (g^a)^b mod p

    That is the core magic of Diffie-Hellman.
    """
    return pow(peer_public, private, p)


def int_to_bytes(n: int) -> bytes:
    """Convert a positive integer to a big-endian byte string.

    Used to transmit DH public values over the wire and to convert
    the shared secret to bytes for later use as key material.
    """
    # Compute the number of bytes needed to represent the integer.
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, "big")


def bytes_to_int(b: bytes) -> int:
    """Convert a big-endian byte string back to an integer."""
    return int.from_bytes(b, "big")
