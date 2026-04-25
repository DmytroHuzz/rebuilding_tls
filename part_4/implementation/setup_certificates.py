# setup_certificates.py
#
# PART 4 — CERTIFICATE SETUP
#
# Run this script ONCE before starting the server and client.
# It generates a complete certificate chain and saves the files to disk:
#
#   certs/root_cert.pem          — trusted root (client keeps this)
#   certs/intermediate_cert.pem  — intermediate CA cert (server sends this)
#   certs/server_cert.pem        — server certificate (server sends this)
#   certs/server_key.pem         — server private key (server keeps this)
#
# In a real TLS deployment:
#   - The root cert is pre-installed in the client's trust store.
#   - The server holds its private key and sends its cert + intermediates.
#   - The client verifies the chain back to its trusted root.
#
# HOW TO RUN:
#   python setup_certificates.py

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "implementation"))

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

import certificate

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
DNS_NAME = "localhost"


def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)

    # ── Root CA ──────────────────────────────────────────────────
    root_name = certificate.CertificateName(
        country_name="AT",
        state_or_province_name="Vorarlberg",
        locality_name="Dornbirn",
        organization_name="Rebuilt TLS",
        common_name="Root CA",
    )
    root_key = generate_rsa_key()
    root_cert = certificate.issue_certificate(
        public_key=root_key.public_key(),
        subject=root_name,
        issuer=root_name,
        issuer_private_key=root_key,
        extensions=certificate.ca_extensions(
            root_key.public_key(), path_length=1
        ),
        validity_from=now,
        validity_to=now + timedelta(days=365 * 10),
    )

    # ── Intermediate CA ──────────────────────────────────────────
    intermediate_name = certificate.CertificateName(
        country_name="AT",
        state_or_province_name="Vorarlberg",
        locality_name="Dornbirn",
        organization_name="Rebuilt TLS",
        common_name="Intermediate CA",
    )
    intermediate_key = generate_rsa_key()
    intermediate_cert = certificate.issue_certificate(
        public_key=intermediate_key.public_key(),
        subject=intermediate_name,
        issuer=root_name,
        issuer_private_key=root_key,
        extensions=certificate.ca_extensions(
            public_key=intermediate_key.public_key(),
            issuer_certificate=root_cert,
            path_length=0,
        ),
        validity_from=now,
        validity_to=now + timedelta(days=365 * 5),
    )

    # ── Server (end-entity) certificate ──────────────────────────
    server_name = certificate.CertificateName(
        country_name="AT",
        state_or_province_name="Vorarlberg",
        locality_name="Dornbirn",
        organization_name="Rebuilt TLS",
        common_name=DNS_NAME,
    )
    server_key = generate_rsa_key()
    server_cert = certificate.issue_certificate(
        public_key=server_key.public_key(),
        subject=server_name,
        issuer=intermediate_name,
        issuer_private_key=intermediate_key,
        extensions=certificate.server_extensions(
            public_key=server_key.public_key(),
            dns_names=[DNS_NAME],
            issuer_certificate=intermediate_cert,
        ),
        validity_from=now,
        validity_to=now + timedelta(days=365 * 2),
    )

    # ── Verify the chain before writing (sanity check) ───────────
    certificate.verify_server_certificate(
        root_certificate=root_cert,
        intermediate_certificates=[intermediate_cert],
        server_certificate=server_cert,
        dns_name=DNS_NAME,
        validation_time=now,
    )
    print("Certificate chain verified successfully.")

    # ── Write files ──────────────────────────────────────────────
    with open(os.path.join(CERTS_DIR, "root_cert.pem"), "wb") as f:
        f.write(root_cert.public_bytes(Encoding.PEM))
    print(f"  Wrote {CERTS_DIR}/root_cert.pem")

    with open(os.path.join(CERTS_DIR, "intermediate_cert.pem"), "wb") as f:
        f.write(intermediate_cert.public_bytes(Encoding.PEM))
    print(f"  Wrote {CERTS_DIR}/intermediate_cert.pem")

    with open(os.path.join(CERTS_DIR, "server_cert.pem"), "wb") as f:
        f.write(server_cert.public_bytes(Encoding.PEM))
    print(f"  Wrote {CERTS_DIR}/server_cert.pem")

    with open(os.path.join(CERTS_DIR, "server_key.pem"), "wb") as f:
        f.write(
            server_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
    print(f"  Wrote {CERTS_DIR}/server_key.pem")

    print("\nDone. You can now run server_v4.py and client_v4.py.")


if __name__ == "__main__":
    main()
