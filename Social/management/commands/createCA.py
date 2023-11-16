from django.core.management.base import BaseCommand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


class Command(BaseCommand):
    """
    A Django management command to create a Certificate Authority (CA).

    This command generates a new private key and a self-signed certificate
    for the CA, and stores them in PEM format. The CA is used for signing
    and verifying certificates in the application.
    """
    help = 'Creates a Certificate Authority (CA) for the application.'

    def handle(self, *args, **kwargs):
        """
        Handle the command to create a Certificate Authority.
        """
        # Generate private and public keys for the CA
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Certificate information setup
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MiniBizum"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"MiniBizum CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Save the CA's private key and certificate to files
        with open("keys/certificates/CA/ca_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        
        with open("keys/certificates/CA/ca_certificate.pem", "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        self.stdout.write(self.style.SUCCESS('CA creada con éxito'))