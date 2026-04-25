from datetime import datetime, timedelta, timezone

import certificate
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_key():
    """Generate an RSA key pair suitable for this educational TLS example."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


now = datetime.now(timezone.utc)
dns_name = "www.rebuilt-tls.com"

# 1. Create the trust anchor.
#
# A root CA certificate is self-signed: the subject and issuer are the same
# name, and the root private key signs the certificate.  Real operating systems
# and browsers ship with many trusted roots.  In this toy example we trust only
# the root certificate generated below.
root_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name="Root CA",
)
root_key = generate_rsa_key()
root_certificate = certificate.issue_certificate(
    public_key=root_key.public_key(),
    subject=root_name,
    issuer=root_name,
    issuer_private_key=root_key,
    # The root may create one more CA level below it: the intermediate.
    extensions=certificate.ca_extensions(root_key.public_key(), path_length=1),
    validity_from=now,
    validity_to=now + timedelta(days=365 * 10),
)

# 2. Create an intermediate CA.
#
# The intermediate is also a CA, but it is not self-signed.  Its issuer is the
# root CA, so the root private key signs this certificate.  This mirrors how
# public roots usually delegate day-to-day certificate issuance.
intermediate_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name="Intermediate CA",
)
intermediate_key = generate_rsa_key()
intermediate_certificate = certificate.issue_certificate(
    public_key=intermediate_key.public_key(),
    subject=intermediate_name,
    issuer=root_name,
    issuer_private_key=root_key,
    extensions=certificate.ca_extensions(
        public_key=intermediate_key.public_key(),
        issuer_certificate=root_certificate,
        # The intermediate may issue leaf certificates, but not more CAs.
        path_length=0,
    ),
    validity_from=now,
    validity_to=now + timedelta(days=365 * 5),
)

# 3. Create the server certificate.
#
# This certificate represents the TLS server for dns_name.  It is an end-entity
# certificate: it can authenticate a server, but it cannot sign another
# certificate.  The intermediate CA signs it.
server_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name=dns_name,
)
server_key = generate_rsa_key()
server_certificate = certificate.issue_certificate(
    public_key=server_key.public_key(),
    subject=server_name,
    issuer=intermediate_name,
    issuer_private_key=intermediate_key,
    extensions=certificate.server_extensions(
        public_key=server_key.public_key(),
        dns_names=[dns_name],
        issuer_certificate=intermediate_certificate,
    ),
    validity_from=now,
    validity_to=now + timedelta(days=365 * 2),
)

# 4. Verify the chain as a TLS client would.
#
# The verifier receives the server certificate plus the intermediate chain from
# the server.  It already has the trusted root locally.  Verification checks the
# signatures, validity dates, CA constraints, key usages, and requested DNS name.
verified_chain = certificate.verify_server_certificate(
    root_certificate=root_certificate,
    intermediate_certificates=[intermediate_certificate],
    server_certificate=server_certificate,
    dns_name=dns_name,
    validation_time=now,
)

print(f"Verified certificate chain length: {len(verified_chain)}")
