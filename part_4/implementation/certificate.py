"""Small X.509 helpers for the certificate-chain walkthrough.

The code in this module intentionally keeps the PKI model visible:

* a certificate binds a subject name and public key together;
* an issuer signs that binding with its private key;
* CA certificates are allowed to sign other certificates;
* end-entity/server certificates are allowed to identify one TLS server.

Reference:
https://cryptography.io/en/latest/x509/tutorial/
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import DNSName, Extension
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store


@dataclass(frozen=True)
class CertificateName:
    """Human-readable subject/issuer fields used inside a certificate.

    X.509 names are ordered collections of attributes.  For the walkthrough we
    keep the common fields explicit instead of accepting arbitrary attributes,
    because that makes every generated certificate easier to inspect.
    """

    country_name: str
    state_or_province_name: str
    locality_name: str
    organization_name: str
    common_name: str

    @property
    def certificate_name(self) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )


def create_certificate_builder(
    public_key: CertificatePublicKeyTypes,
    subject: CertificateName,
    issuer: CertificateName,
    extensions: Iterable[Extension],
    validity_to: datetime,
    validity_from: datetime | None = None,
) -> x509.CertificateBuilder:
    """Create the unsigned certificate data that an issuer will sign.

    This is not a CSR.  A real CSR is created by the subject and signed with the
    subject's private key.  Here we build the final certificate body directly so
    the walkthrough can focus on chain construction and verification.
    """
    valid_from = validity_from or datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject.certificate_name)
        .issuer_name(issuer.certificate_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(validity_to)
    )

    for extension in extensions:
        # Re-add the Extension object as its value + critical flag because the
        # builder API stores extensions that way.
        builder = builder.add_extension(extension.value, critical=extension.critical)

    return builder


def sign_certificate(
    builder: x509.CertificateBuilder,
    issuer_private_key: CertificateIssuerPrivateKeyTypes,
) -> x509.Certificate:
    """Sign a certificate with the issuer's private key.

    The private key used here must correspond to the issuer public key.  For a
    self-signed root certificate, subject and issuer are the same entity and the
    root signs itself.
    """
    return builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())


def issue_certificate(
    public_key: CertificatePublicKeyTypes,
    subject: CertificateName,
    issuer: CertificateName,
    issuer_private_key: CertificateIssuerPrivateKeyTypes,
    extensions: Iterable[Extension],
    validity_to: datetime,
    validity_from: datetime | None = None,
) -> x509.Certificate:
    """Build and sign one certificate in the chain."""
    builder = create_certificate_builder(
        public_key=public_key,
        subject=subject,
        issuer=issuer,
        extensions=extensions,
        validity_to=validity_to,
        validity_from=validity_from,
    )
    return sign_certificate(builder=builder, issuer_private_key=issuer_private_key)


def ca_extensions(
    public_key: CertificatePublicKeyTypes,
    issuer_certificate: x509.Certificate | None = None,
    path_length: int | None = None,
) -> list[Extension]:
    """Return the extensions that make a certificate act as a CA.

    ``BasicConstraints(ca=True)`` is what allows this certificate to issue
    other certificates.  ``KeyUsage`` narrows that permission to certificate and
    revocation-list signing.  ``SubjectKeyIdentifier`` names this CA's key, and
    ``AuthorityKeyIdentifier`` points to the parent CA key when there is one.
    """
    extensions = [
        Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=True, path_length=path_length),
        ),
        Extension(
            oid=x509.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(public_key),
        ),
    ]

    if issuer_certificate is not None:
        extensions.append(
            Extension(
                oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                critical=False,
                value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_certificate.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
            )
        )

    return extensions


def server_extensions(
    public_key: CertificatePublicKeyTypes,
    dns_names: Sequence[str],
    issuer_certificate: x509.Certificate,
) -> list[Extension]:
    """Return the extensions expected on a TLS server certificate.

    Modern clients verify DNS names through Subject Alternative Name (SAN), not
    the legacy Common Name field.  Extended Key Usage marks the certificate as a
    TLS server certificate, and Basic Constraints prevents it from acting as a
    CA in the chain.
    """
    return [
        Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=False, path_length=None),
        ),
        Extension(
            oid=x509.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName([DNSName(name) for name in dns_names]),
        ),
        Extension(
            oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(public_key),
        ),
    ]


def verify_server_certificate(
    root_certificate: x509.Certificate,
    intermediate_certificates: Sequence[x509.Certificate],
    server_certificate: x509.Certificate,
    dns_name: str,
    validation_time: datetime | None = None,
) -> list[x509.Certificate]:
    """Verify a server certificate chains back to a trusted root.

    ``root_certificate`` is the local trust anchor.  ``intermediate_certificates``
    are sent by the server during a TLS handshake.  ``server_certificate`` is the
    leaf certificate being checked for the requested ``dns_name``.
    """
    store = Store([root_certificate])
    builder = PolicyBuilder().store(store)

    if validation_time is not None:
        builder = builder.time(validation_time)

    verifier = builder.build_server_verifier(DNSName(dns_name))
    return verifier.verify(server_certificate, intermediate_certificates)


def create_certificate_signing_request(
    public_key: CertificatePublicKeyTypes,
    subject: CertificateName,
    issuer: CertificateName,
    extensions: Iterable[Extension],
    validity_to: datetime,
) -> x509.CertificateBuilder:
    """Backward-compatible alias for the old walkthrough helper name.

    The returned object is a certificate builder, not a real certificate signing
    request.  New code should call ``create_certificate_builder``.
    """
    return create_certificate_builder(
        public_key=public_key,
        subject=subject,
        issuer=issuer,
        extensions=extensions,
        validity_to=validity_to,
    )


def sign_certificate_signing_request(
    csr: x509.CertificateBuilder,
    private_key: CertificateIssuerPrivateKeyTypes,
) -> x509.Certificate:
    """Backward-compatible alias for the old walkthrough helper name."""
    return sign_certificate(builder=csr, issuer_private_key=private_key)


def verify_certificate(
    root_certificate: x509.Certificate,
    intermediate_certificates: Sequence[x509.Certificate],
    end_entity_certificate: x509.Certificate,
    dns_name: str,
) -> int:
    """Backward-compatible helper returning only the verified chain length."""
    chain = verify_server_certificate(
        root_certificate=root_certificate,
        intermediate_certificates=intermediate_certificates,
        server_certificate=end_entity_certificate,
        dns_name=dns_name,
    )
    return len(chain)
