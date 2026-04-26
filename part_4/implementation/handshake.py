# handshake.py
#
# PART 4 — AUTHENTICATED HANDSHAKE
#
# WHAT THIS FILE DOES:
#   Combines the X25519 + HKDF handshake from Part 3 v3 with certificate
#   authentication from Part 4.  After the handshake, both sides have
#   matching session keys AND the client has verified the server's identity.
#
# ─────────────────────────────────────────────────────────────────────────
# TWO COMPLETELY DIFFERENT KINDS OF KEYS LIVE IN THIS FILE
# ─────────────────────────────────────────────────────────────────────────
# It is critical not to mix them up, so we use distinct prefixes everywhere:
#
#   IDENTITY keys  (prefix: identity_*)
#     - Algorithm:  RSA  (long-term, RSA-2048 in this project)
#     - Lifetime:   years — same key on every connection
#     - Owner:      ONLY the server.  Stored on disk, certified by a CA.
#     - Purpose:    PROVE WHO THE SERVER IS.
#                   The server signs handshake bytes with its identity
#                   private key so the client can verify the server holds
#                   the key that matches the certificate.
#     - Public half:  embedded inside the X.509 certificate.
#     - Private half: NEVER leaves the server.
#
#   EPHEMERAL keys (prefix: ephemeral_*)
#     - Algorithm:  X25519  (Diffie–Hellman over Curve25519)
#     - Lifetime:   one connection.  Generated, used, discarded.
#     - Owner:      BOTH sides generate their own.
#     - Purpose:    AGREE ON A SHARED SECRET for this session,
#                   from which AES-GCM session keys are derived.
#     - Public half:  exchanged on the wire (ClientHello / ServerHello).
#     - Private half: kept only in memory for the lifetime of the handshake.
#
# Why both?
#   - Identity keys give us AUTHENTICATION ("you really are localhost").
#   - Ephemeral keys give us FORWARD SECRECY:  if the server's identity
#     private key is stolen tomorrow, recordings of today's traffic still
#     can't be decrypted, because the X25519 private keys are long gone.
# ─────────────────────────────────────────────────────────────────────────
#
# THE FULL PIPELINE:
#
#   ClientHello  (client → server)
#     └── EPHEMERAL X25519 public key  (client_ephemeral_public)
#
#   ServerHello  (server → client)
#     └── EPHEMERAL X25519 public key  (server_ephemeral_public)
#
#   ServerAuth   (server → client)
#     ├── server IDENTITY certificate    (DER, contains the RSA public key)
#     ├── intermediate CA certificates   (DER)
#     └── CertificateVerify — RSA-PSS signature, made with the IDENTITY
#         private key, over:
#             client_ephemeral_public || server_ephemeral_public
#         (this is the bridge that ties identity to this session)
#
#   The client then:
#     1. Verifies the certificate chain against its trusted root
#        → trusts the IDENTITY public key inside the server cert.
#     2. Verifies the CertificateVerify signature with that IDENTITY
#        public key → proves the peer holds the matching private key
#        AND that it signed THESE specific ephemeral keys.
#
#   Both sides then derive session keys via HKDF from the shared secret.
#
# WHAT CHANGED FROM PART 3 v3:
#   Part 3 v3 had NO authentication.  A man-in-the-middle could intercept
#   the ClientHello and ServerHello, substitute its own X25519 public
#   keys, and establish separate sessions with the client and server.
#
#   Part 4 stops this because:
#   - The server proves its IDENTITY via an X.509 certificate chain.
#   - The server signs the EPHEMERAL public keys with its identity key,
#     so a MITM cannot swap them without the signature failing.
#
# WHAT IS STILL SIMPLIFIED:
#   - Only server authentication (client is anonymous, like most HTTPS).
#   - No transcript hash — we sign only the ephemeral public keys, not a
#     full handshake transcript.  Real TLS 1.3 hashes ALL handshake
#     messages into the signature.
#   - No cipher suite negotiation, no extensions, no HelloRetryRequest.

import sys
import os

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "part_3", "common")
)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "implementation"))

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from framing import send_record, recv_record
from handshake_messages import (
    encode_message,
    decode_message,
    TAG_X25519_PUBLIC,
)
from utils import hex_preview
from part_4.implementation.key_schedule import derive_session_keys
import certificate

# New handshake message tags for certificate authentication.
TAG_CERTIFICATE = 0x0020  # DER-encoded X.509 certificate
TAG_CERTIFICATE_VERIFY = 0x0021  # RSA-PSS signature over exchanged ephemeral pubkeys


# ─────────────────────────────────────────────────────────────────────
# CertificateVerify: signing/verifying with the IDENTITY key
# ─────────────────────────────────────────────────────────────────────
#
# These two helpers operate purely on the IDENTITY (RSA) keys.
# They never touch the X25519 ephemeral keys directly — they only
# read/write the wire-format BYTES of those ephemeral public keys.


def _sign_ephemeral_pubkeys_with_identity(
    identity_private_key: rsa.RSAPrivateKey,
    client_ephemeral_public_bytes: bytes,
    server_ephemeral_public_bytes: bytes,
) -> bytes:
    """Sign the two EPHEMERAL X25519 public keys using the IDENTITY (RSA) key.

    The signature is produced with RSA-PSS over the concatenation of
    the two ephemeral public keys.  This is the bridge between the
    server's long-term identity (the cert) and this specific session's
    ephemeral key exchange.

    Why these bytes?
      - server's ephemeral pubkey is fresh per connection → no replay.
      - client's ephemeral pubkey ties the signature to THIS client's
        contribution → the signature can't be reused on another session.
    """
    data_to_sign = client_ephemeral_public_bytes + server_ephemeral_public_bytes
    return identity_private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verify_ephemeral_pubkeys_with_identity(
    identity_public_key: rsa.RSAPublicKey,
    signature: bytes,
    client_ephemeral_public_bytes: bytes,
    server_ephemeral_public_bytes: bytes,
) -> None:
    """Verify the CertificateVerify signature using the IDENTITY public key
    (extracted from the already-validated server certificate).

    Raises an exception if the signature is invalid.
    """
    data_that_was_signed = client_ephemeral_public_bytes + server_ephemeral_public_bytes
    identity_public_key.verify(
        signature,
        data_that_was_signed,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


# ─────────────────────────────────────────────────────────────────────
# Client-side handshake
# ─────────────────────────────────────────────────────────────────────


def client_handshake(
    sock,
    trusted_root: x509.Certificate,
    dns_name: str,
) -> tuple:
    """Client-side authenticated handshake.

    The client never owns an identity key — it only TRUSTS the server's
    identity (transitively, via the trusted root).  It does, however,
    own its own EPHEMERAL X25519 keypair for this one connection.

    Args:
        sock:         Connected TCP socket.
        trusted_root: Root CA certificate the client trusts (the trust
                      anchor used to validate the server's identity chain).
        dns_name:     Hostname the client expects the server's IDENTITY
                      certificate to cover.

    Returns:
        (client_write_key, server_write_key) — each 32 bytes, derived
        from the X25519 shared secret.
    """
    print("\n[handshake] Client: starting authenticated handshake")

    # ── Step 1: EPHEMERAL X25519 key exchange ────────────────────
    # These keys exist only for this connection.  Their private half
    # never leaves this process; their public half goes on the wire.

    client_ephemeral_private = X25519PrivateKey.generate()
    client_ephemeral_public_bytes = client_ephemeral_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    print(f"  Generated EPHEMERAL X25519 keypair (this session only)")
    print(f"  client_ephemeral_public: {hex_preview(client_ephemeral_public_bytes)}")

    # Send ClientHello — carries only the ephemeral public key.
    client_hello = encode_message([(TAG_X25519_PUBLIC, client_ephemeral_public_bytes)])
    send_record(sock, client_hello)
    print(f"  -> Sent ClientHello ({len(client_hello)} bytes)")

    # Receive ServerHello — server's ephemeral X25519 public key.
    server_hello_raw = recv_record(sock)
    fields = decode_message(server_hello_raw)
    server_ephemeral_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            server_ephemeral_public_bytes = value
    if server_ephemeral_public_bytes is None:
        raise ValueError("ServerHello missing X25519 ephemeral public key")

    print(f"  <- Received ServerHello")
    print(f"  server_ephemeral_public: {hex_preview(server_ephemeral_public_bytes)}")

    server_ephemeral_public = X25519PublicKey.from_public_bytes(
        server_ephemeral_public_bytes
    )

    # ── Step 2: Receive and verify server IDENTITY ───────────────
    # ServerAuth carries the server's long-term IDENTITY proof:
    #   - X.509 certificate chain  → identifies the server's RSA public key
    #   - CertificateVerify signature → ties that identity to step 1's
    #                                    ephemeral keys.

    server_auth_raw = recv_record(sock)
    auth_fields = decode_message(server_auth_raw)

    cert_der_list = []
    certificate_verify_signature = None
    for tag, value in auth_fields:
        if tag == TAG_CERTIFICATE:
            cert_der_list.append(value)
        elif tag == TAG_CERTIFICATE_VERIFY:
            certificate_verify_signature = value

    if len(cert_der_list) < 1:
        raise ValueError("ServerAuth missing certificates")
    if certificate_verify_signature is None:
        raise ValueError("ServerAuth missing CertificateVerify signature")

    # Parse DER certificates.
    server_identity_cert = x509.load_der_x509_certificate(cert_der_list[0])
    intermediate_certs = [
        x509.load_der_x509_certificate(der) for der in cert_der_list[1:]
    ]

    print(f"  <- Received ServerAuth")
    print(f"    server identity cert subject: {server_identity_cert.subject}")
    print(f"    intermediate certs: {len(intermediate_certs)}")

    # 2a. Verify the IDENTITY certificate chain back to the trusted root.
    #     After this passes, we trust the RSA public key inside server_identity_cert.
    print(f"  Verifying IDENTITY certificate chain for '{dns_name}'...")
    certificate.verify_server_certificate(
        root_certificate=trusted_root,
        intermediate_certificates=intermediate_certs,
        server_certificate=server_identity_cert,
        dns_name=dns_name,
    )
    print(f"  Identity certificate chain: VALID")

    # 2b. Verify the CertificateVerify signature using the IDENTITY public
    #     key from the now-trusted certificate.  This proves:
    #       (a) the peer holds the IDENTITY private key, and
    #       (b) it signed THESE specific EPHEMERAL public keys (not stale
    #           replays).
    print(f"  Verifying CertificateVerify (binds identity → this session)...")
    server_identity_public_key = server_identity_cert.public_key()
    _verify_ephemeral_pubkeys_with_identity(
        identity_public_key=server_identity_public_key,
        signature=certificate_verify_signature,
        client_ephemeral_public_bytes=client_ephemeral_public_bytes,
        server_ephemeral_public_bytes=server_ephemeral_public_bytes,
    )
    print(f"  CertificateVerify: VALID — peer is the real '{dns_name}'")

    # ── Step 3: Derive session keys from EPHEMERAL X25519 secret ─
    # The IDENTITY keys are not used past this point.  All bulk
    # encryption uses keys derived from the ephemeral X25519 secret.

    shared_secret = client_ephemeral_private.exchange(server_ephemeral_public)
    print(f"  X25519 shared secret: {hex_preview(shared_secret)}")

    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Client: handshake complete — authenticated session keys ready\n")

    return client_write_key, server_write_key


# ─────────────────────────────────────────────────────────────────────
# Server-side handshake
# ─────────────────────────────────────────────────────────────────────


def server_handshake(
    sock,
    server_identity_private_key: rsa.RSAPrivateKey,
    server_identity_cert: x509.Certificate,
    intermediate_certs: list[x509.Certificate],
) -> tuple:
    """Server-side authenticated handshake.

    The server owns TWO completely separate kinds of keys here:

      * IDENTITY  (RSA, long-term):
            server_identity_private_key  (loaded from disk)
            server_identity_cert         (loaded from disk)
        Used to PROVE who we are by signing CertificateVerify.

      * EPHEMERAL (X25519, this connection only):
            server_ephemeral_private  (generated below)
        Used to AGREE on a shared secret with the client.

    Args:
        sock:                          Connected TCP socket.
        server_identity_private_key:   RSA private key matching the cert.
                                       NEVER leaves this process.
        server_identity_cert:          End-entity X.509 cert (sent to client).
        intermediate_certs:            Intermediate CA certs (sent to client
                                       so the chain can be built up to the
                                       client's trusted root).

    Returns:
        (client_write_key, server_write_key) — each 32 bytes.
    """
    print("\n[handshake] Server: starting authenticated handshake")

    # ── Step 1: Generate the EPHEMERAL X25519 keypair ────────────
    # Brand new for this connection.  Has NOTHING to do with the RSA
    # identity key — different algorithm, different lifetime, different
    # purpose.

    server_ephemeral_private = X25519PrivateKey.generate()
    server_ephemeral_public_bytes = server_ephemeral_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    print(f"  Generated EPHEMERAL X25519 keypair (this session only)")
    print(f"  server_ephemeral_public: {hex_preview(server_ephemeral_public_bytes)}")

    # Receive ClientHello (client's ephemeral X25519 public key).
    client_hello_raw = recv_record(sock)
    fields = decode_message(client_hello_raw)
    client_ephemeral_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            client_ephemeral_public_bytes = value
    if client_ephemeral_public_bytes is None:
        raise ValueError("ClientHello missing X25519 ephemeral public key")

    print(f"  <- Received ClientHello")
    print(f"  client_ephemeral_public: {hex_preview(client_ephemeral_public_bytes)}")

    client_ephemeral_public = X25519PublicKey.from_public_bytes(
        client_ephemeral_public_bytes
    )

    # Send ServerHello (our ephemeral X25519 public key).
    server_hello = encode_message([(TAG_X25519_PUBLIC, server_ephemeral_public_bytes)])
    send_record(sock, server_hello)
    print(f"  -> Sent ServerHello ({len(server_hello)} bytes)")

    # ── Step 2: Prove IDENTITY: send chain + CertificateVerify ───
    # The IDENTITY key signs the EPHEMERAL public keys.  This is the
    # only place the two key worlds touch each other.

    certificate_verify_signature = _sign_ephemeral_pubkeys_with_identity(
        identity_private_key=server_identity_private_key,
        client_ephemeral_public_bytes=client_ephemeral_public_bytes,
        server_ephemeral_public_bytes=server_ephemeral_public_bytes,
    )

    # Build the ServerAuth message:
    #   - leaf identity certificate (DER)
    #   - intermediate certificates (DER)
    #   - CertificateVerify signature
    auth_fields = [
        (TAG_CERTIFICATE, server_identity_cert.public_bytes(Encoding.DER)),
    ]
    for intermediate_cert in intermediate_certs:
        auth_fields.append(
            (TAG_CERTIFICATE, intermediate_cert.public_bytes(Encoding.DER))
        )
    auth_fields.append((TAG_CERTIFICATE_VERIFY, certificate_verify_signature))

    server_auth = encode_message(auth_fields)
    send_record(sock, server_auth)
    print(f"  -> Sent ServerAuth ({len(server_auth)} bytes)")
    print(
        f"    identity certs: {1 + len(intermediate_certs)}, "
        f"CertificateVerify: {len(certificate_verify_signature)}B"
    )

    # ── Step 3: Derive session keys from EPHEMERAL X25519 secret ─
    # IDENTITY keys are done.  From here on, only the ephemeral
    # shared secret matters (this is what gives us forward secrecy).

    shared_secret = server_ephemeral_private.exchange(client_ephemeral_public)
    print(f"  X25519 shared secret: {hex_preview(shared_secret)}")

    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Server: handshake complete — session keys ready\n")

    return client_write_key, server_write_key
