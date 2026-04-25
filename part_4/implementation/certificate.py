"""The certificate related functions
Based on Python oficial documentation:
https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr
"""

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store


class CertificateName:
    certificate_name: x509.Name

    def __init__(
        self,
        country_name,
        state_or_province_name,
        locality_name,
        organization_name,
        common_name,
    ):
        self.certificate_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )


def create_certificate_signing_request(
    public_key: str,
    subject: CertificateName,
    issuer: CertificateName,
    extensions: list[x509.Extension],
    validity_to: datetime,
):
    """Create a certificate signing request that will be signed by authority"""
    csr = (
        x509.CertificateBuilder()
        .subject_name(subject.certificate_name)
        .issuer_name(issuer.certificate_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(validity_to)
    )
    for extension in extensions:
        csr = csr.add_extension(extension.value, critical=extension.critical)
    return csr


def sign_certificate_signing_request(csr, private_key):
    """Sign certificate by CA private key"""
    certificate = csr.sign(private_key, hashes.SHA256())
    return certificate


def verify_certificate(
    root_certificate, intermediate_certificates, end_entity_certificate, dns_name
):
    """Verify the certificate/chain of certificates"""
    store = Store([root_certificate])
    builder = PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(DNSName(dns_name))
    chain = verifier.verify(end_entity_certificate, intermediate_certificates)
    return len(chain)
