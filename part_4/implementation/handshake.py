# handshake.py
#
# PART 4 — AUTHENTICATED HANDSHAKE
#
# WHAT THIS FILE DOES:
#   Combines the X25519 + HKDF handshake from Part 3 v3 with certificate
#   authentication from Part 4.  After the handshake, both sides have
#   matching session keys AND the client has verified the server's identity.
#
# THE FULL PIPELINE:
#
#   ClientHello  (client → server)
#     └── X25519 ephemeral public key
#
#   ServerHello  (server → client)
#     └── X25519 ephemeral public key
#
#   ServerAuth   (server → client)
#     ├── server certificate      (DER)
#     ├── intermediate certificate (DER)
#     └── CertificateVerify — RSA-PSS signature over:
#             client_public || server_public
#
#   The client then:
#     1. Verifies the certificate chain against its trusted root.
#     2. Extracts the server's public key from the verified certificate.
#     3. Verifies the CertificateVerify signature, which proves the server
#        holds the private key that matches the certificate.
#
#   Both sides then derive session keys via HKDF from the shared secret.
#
# WHAT CHANGED FROM PART 3 v3:
#   Part 3 v3 had NO authentication.  A man-in-the-middle could intercept
#   the ClientHello and ServerHello, substitute its own public keys, and
#   establish separate sessions with the client and server.
#
#   Part 4 stops this because:
#   - The server proves its identity via a certificate chain.
#   - The server signs the exchanged public keys, so a MITM cannot
#     substitute them without the signature failing.
#
# WHAT IS STILL SIMPLIFIED:
#   - Only server authentication (client is anonymous, like most HTTPS).
#   - No transcript hash — we sign only the public keys, not a full
#     handshake transcript.  Real TLS 1.3 includes a hash of all
#     handshake messages.
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
from key_schedule import derive_session_keys
import certificate

# New handshake message tags for certificate authentication.
TAG_CERTIFICATE = 0x0020  # DER-encoded X.509 certificate
TAG_CERTIFICATE_VERIFY = 0x0021  # RSA-PSS signature over exchanged public keys


def _sign_public_keys(
    server_private_key: rsa.RSAPrivateKey,
    client_public_bytes: bytes,
    server_public_bytes: bytes,
) -> bytes:
    """Sign the concatenation of both X25519 public keys with RSA-PSS.

    This proves to the client that the server holds the private key
    corresponding to its certificate, AND that it participated in this
    specific key exchange (not a replayed one).
    """
    data = client_public_bytes + server_public_bytes
    return server_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verify_signature(
    public_key: rsa.RSAPublicKey,
    signature: bytes,
    client_public_bytes: bytes,
    server_public_bytes: bytes,
) -> None:
    """Verify the CertificateVerify signature.

    Raises an exception if the signature is invalid.
    """
    data = client_public_bytes + server_public_bytes
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def client_handshake(
    sock,
    trusted_root: x509.Certificate,
    dns_name: str,
) -> tuple:
    """Client-side authenticated handshake.

    Args:
        sock:         Connected TCP socket.
        trusted_root: The root CA certificate the client trusts.
        dns_name:     The hostname the client expects the server to prove.

    Returns:
        (client_write_key, server_write_key) — each 32 bytes.
    """
    print("\n[handshake] Client: starting authenticated handshake")

    # ── Step 1: X25519 key exchange ──────────────────────────────

    client_private = X25519PrivateKey.generate()
    client_public = client_private.public_key()
    client_public_bytes = client_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Client public key: {hex_preview(client_public_bytes)}")

    # Send ClientHello.
    client_hello = encode_message([(TAG_X25519_PUBLIC, client_public_bytes)])
    send_record(sock, client_hello)
    print(f"  -> Sent ClientHello ({len(client_hello)} bytes)")

    # Receive ServerHello.
    server_hello_raw = recv_record(sock)
    fields = decode_message(server_hello_raw)
    server_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            server_public_bytes = value
    if server_public_bytes is None:
        raise ValueError("ServerHello missing X25519 public key")

    print(f"  <- Received ServerHello")
    print(f"  Server public key: {hex_preview(server_public_bytes)}")

    server_public = X25519PublicKey.from_public_bytes(server_public_bytes)

    # ── Step 2: Receive and verify server authentication ─────────

    server_auth_raw = recv_record(sock)
    auth_fields = decode_message(server_auth_raw)

    # Extract certificates and signature from the message.
    cert_der_list = []
    signature = None
    for tag, value in auth_fields:
        if tag == TAG_CERTIFICATE:
            cert_der_list.append(value)
        elif tag == TAG_CERTIFICATE_VERIFY:
            signature = value

    if len(cert_der_list) < 1:
        raise ValueError("ServerAuth missing certificates")
    if signature is None:
        raise ValueError("ServerAuth missing CertificateVerify signature")

    # Parse DER certificates.
    server_cert = x509.load_der_x509_certificate(cert_der_list[0])
    intermediate_certs = [
        x509.load_der_x509_certificate(der) for der in cert_der_list[1:]
    ]

    print(f"  <- Received ServerAuth")
    print(f"    Server cert subject: {server_cert.subject}")
    print(f"    Intermediate certs: {len(intermediate_certs)}")

    # 2a. Verify the certificate chain against the trusted root.
    print(f"  Verifying certificate chain for '{dns_name}'...")
    certificate.verify_server_certificate(
        root_certificate=trusted_root,
        intermediate_certificates=intermediate_certs,
        server_certificate=server_cert,
        dns_name=dns_name,
    )
    print(f"  Certificate chain: VALID")

    # 2b. Verify the CertificateVerify signature.
    #     This proves the server holds the private key for the certificate
    #     AND that these specific public keys were exchanged (anti-MITM).
    print(f"  Verifying CertificateVerify signature...")
    server_rsa_public_key = server_cert.public_key()
    _verify_signature(
        server_rsa_public_key, signature, client_public_bytes, server_public_bytes
    )
    print(f"  CertificateVerify: VALID")

    # ── Step 3: Compute shared secret and derive session keys ────

    shared_secret = client_private.exchange(server_public)
    print(f"  Shared secret: {hex_preview(shared_secret)}")

    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Client: handshake complete — authenticated session keys ready\n")

    return client_write_key, server_write_key


def server_handshake(
    sock,
    server_private_key: rsa.RSAPrivateKey,
    server_cert: x509.Certificate,
    intermediate_certs: list[x509.Certificate],
) -> tuple:
    """Server-side authenticated handshake.

    Args:
        sock:               Connected TCP socket.
        server_private_key: The RSA private key matching server_cert.
        server_cert:        The server's end-entity certificate.
        intermediate_certs: Intermediate CA certificates to send to the client.

    Returns:
        (client_write_key, server_write_key) — each 32 bytes.
    """
    print("\n[handshake] Server: starting authenticated handshake")

    # ── Step 1: X25519 key exchange ──────────────────────────────

    server_private = X25519PrivateKey.generate()
    server_public = server_private.public_key()
    server_public_bytes = server_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(f"  Generated ephemeral keypair")
    print(f"  Server public key: {hex_preview(server_public_bytes)}")

    # Receive ClientHello.
    client_hello_raw = recv_record(sock)
    fields = decode_message(client_hello_raw)
    client_public_bytes = None
    for tag, value in fields:
        if tag == TAG_X25519_PUBLIC:
            client_public_bytes = value
    if client_public_bytes is None:
        raise ValueError("ClientHello missing X25519 public key")

    print(f"  <- Received ClientHello")
    print(f"  Client public key: {hex_preview(client_public_bytes)}")

    client_public = X25519PublicKey.from_public_bytes(client_public_bytes)

    # Send ServerHello.
    server_hello = encode_message([(TAG_X25519_PUBLIC, server_public_bytes)])
    send_record(sock, server_hello)
    print(f"  -> Sent ServerHello ({len(server_hello)} bytes)")

    # ── Step 2: Send certificate chain + signature ───────────────

    # Sign the concatenation of both public keys.
    signature = _sign_public_keys(
        server_private_key, client_public_bytes, server_public_bytes
    )

    # Build the ServerAuth message:
    #   - server certificate (DER)
    #   - intermediate certificates (DER)
    #   - CertificateVerify signature
    auth_fields = [
        (TAG_CERTIFICATE, server_cert.public_bytes(Encoding.DER)),
    ]
    for cert in intermediate_certs:
        auth_fields.append((TAG_CERTIFICATE, cert.public_bytes(Encoding.DER)))
    auth_fields.append((TAG_CERTIFICATE_VERIFY, signature))

    server_auth = encode_message(auth_fields)
    send_record(sock, server_auth)
    print(f"  -> Sent ServerAuth ({len(server_auth)} bytes)")
    print(
        f"    Certificates: {1 + len(intermediate_certs)}, Signature: {len(signature)}B"
    )

    # ── Step 3: Compute shared secret and derive session keys ────

    shared_secret = server_private.exchange(client_public)
    print(f"  Shared secret: {hex_preview(shared_secret)}")

    client_write_key, server_write_key = derive_session_keys(shared_secret)

    print("[handshake] Server: handshake complete — session keys ready\n")

    return client_write_key, server_write_key
