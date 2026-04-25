from datetime import datetime, timedelta, timezone

import certificate
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509


root_certificate_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name="Root CA",
)

root_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
root_csr = certificate.create_certificate_signing_request(
    public_key=root_key.public_key(),
    subject=root_certificate_name,
    issuer=root_certificate_name,
    extensions=[
        x509.Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=True, path_length=None),
        ),
        x509.Extension(
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
        x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
        ),
    ],
    validity_to=datetime.now(timezone.utc) + timedelta(days=365 * 10),
)

root_certificate = certificate.sign_certificate_signing_request(root_csr, root_key)


intermediate_certificate_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name="Intermediate CA",
)

intermediate_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
intermediate_csr = certificate.create_certificate_signing_request(
    public_key=intermediate_key.public_key(),
    subject=intermediate_certificate_name,
    issuer=root_certificate_name,
    extensions=[
        x509.Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=True, path_length=None),
        ),
        x509.Extension(
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
        x509.Extension(
            oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root_certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
        ),
        x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(
                intermediate_key.public_key()
            ),
        ),
    ],
    validity_to=datetime.now(timezone.utc) + timedelta(days=365 * 5),
)
intermediate_certificate = certificate.sign_certificate_signing_request(
    intermediate_csr, root_key
)

end_entity_certificate_name = certificate.CertificateName(
    country_name="AT",
    state_or_province_name="Vorarlberg",
    locality_name="Dornbirn",
    organization_name="Rebuilt TLS",
    common_name="www.rebuilt-tls.com",
)

end_entity_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
end_entity_csr = certificate.create_certificate_signing_request(
    public_key=end_entity_key.public_key(),
    subject=end_entity_certificate_name,
    issuer=intermediate_certificate_name,
    extensions=[
        x509.Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=False, path_length=None),
        ),
        x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName(
                [
                    # Describe what sites we want this certificate for.
                    x509.DNSName("www.rebuilt-tls.com"),
                ]
            ),
        ),
        x509.Extension(
            oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                intermediate_certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
        ),
        x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(
                end_entity_key.public_key()
            ),
        ),
    ],
    validity_to=datetime.now(timezone.utc) + timedelta(days=365 * 2),
)
end_entity_certificate = certificate.sign_certificate_signing_request(
    end_entity_csr, intermediate_key
)

print(
    certificate.verify_certificate(
        root_certificate=root_certificate,
        intermediate_certificates=[intermediate_certificate],
        end_entity_certificate=end_entity_certificate,
        dns_name="www.rebuilt-tls.com",
    )
)
