from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
import sys
sys.path.append("src")
from models.keyGenerator import KeyGenerator


class CertificateManager:
    """Gestion de la création et de la validation des certificats"""

    def __init__(self, key_generator: KeyGenerator):
        self.key_generator = key_generator

    def createSelfSignedCert(self, subject_name: str, cert_path: str):
        private_key = self.key_generator.generateECKey()
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(public_key).serial_number(
        x509.random_serial_number()
        ).not_valid_before(datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=365)).sign(
            private_key, hashes.SHA256(), default_backend())

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_path

    def loadCertificate(self, cert_path: str) -> x509.Certificate:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            return cert
