from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from typing import Optional


def create_certificate_for_user(user_public_pem: bytes, ca_private_key_pem: bytes, ca_certificate_pem: bytes, user_id: int, username: str, email: str, phone: str) -> bytes:
    """
    Create a certificate for a user's public key.

    Args:
        user_public_pem (bytes): The user's public key in PEM format.
        ca_private_key_pem (bytes): The CA's private key in PEM format.
        ca_certificate_pem (bytes): The CA's certificate in PEM format.

    Returns:
        bytes: The signed certificate in PEM format.
    """

    # Load the user's public key
    user_public_key = load_pem_public_key(user_public_pem, backend=default_backend())

    # Load the CA's private key
    ca_private_key = load_pem_private_key(ca_private_key_pem, password=None, backend=default_backend())

    # Load the CA's certificate
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem, backend=default_backend())

    # Create a builder for the certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MiniBizum"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, phone),
    ])
    certificate_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_certificate.issuer
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    )

    # Sign the certificate with the CA's private key
    user_certificate = certificate_builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # Save the certificate in a file
    with open(f"keys/certificates/user_{user_id}_certificate.pem", "wb") as f:
        f.write(user_certificate.public_bytes(serialization.Encoding.PEM))

    # Return the certificate in PEM format
    return user_certificate.public_bytes(serialization.Encoding.PEM)


def load_ca_private_key_and_certificate() -> tuple[bytes, bytes]:
    """
    Load the private key and certificate of the CA from files.

    Returns:
        tuple[bytes, bytes]: A tuple containing the CA's private key and certificate in PEM format.
    """
    with open('keys/certificates/CA/ca_private_key.pem', 'rb') as key_file:
        ca_private_key_pem = key_file.read()
    with open('keys/certificates/CA/ca_certificate.pem', 'rb') as cert_file:
        ca_certificate_pem = cert_file.read()

    return ca_private_key_pem, ca_certificate_pem


def get_public_key_from_certificate(user_certificate_pem: bytes) -> bytes:
    """
    Extract the public key from a user's certificate.

    Args:
        user_certificate_pem (bytes): The user's certificate in PEM format.

    Returns:
        Public key object.
    """
    certificate = x509.load_pem_x509_certificate(user_certificate_pem, default_backend())
    public_key = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key


def get_user_public_key(user: User) -> Optional[bytes]:
    """
    Retrieve the public key for a given user from their certificate.

    Args:
        user (User): The Django User model instance.

    Returns:
        Optional[bytes]: The public key in PEM format, or None if the user doesn't have a certificate.
    """
    user_certificate_pem = user.profile.certificate
    if user_certificate_pem:
        return get_public_key_from_certificate(user_certificate_pem)
    return None


def verify_certificate(user_certificate_pem: bytes, ca_certificate_pem: bytes) -> bool:
    """
    Verify a user's certificate against the CA's certificate.

    Args:
        user_certificate_pem (bytes): The user's certificate in PEM format.
        ca_certificate_pem (bytes): The CA's certificate in PEM format.

    Returns:
        Boolean: True if valid, False otherwise.
    """
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem, default_backend())
    user_certificate = x509.load_pem_x509_certificate(user_certificate_pem, default_backend())

    # Verify that the certificate has not expired
    if user_certificate.not_valid_before <= datetime.utcnow() <= user_certificate.not_valid_after:
        try:
            # Verify that the certificate was signed by the CA
            ca_public_key = ca_certificate.public_key()
            algorithm = hashes.SHA256()
            ca_public_key.verify(
                user_certificate.signature,
                user_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algorithm
            )
            return True
        except InvalidSignature:
            return False
    return False


def is_certificate_valid(user: User) -> bool:
    """
    Checks if the user's certificate is valid by verifying it against the CA's certificate.

    Args:
        user (User): The Django User model instance.

    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    user_certificate_pem = user.profile.certificate
    _, ca_certificate_pem = load_ca_private_key_and_certificate()
    if user_certificate_pem and ca_certificate_pem:
        return verify_certificate(user_certificate_pem, ca_certificate_pem)
    return False