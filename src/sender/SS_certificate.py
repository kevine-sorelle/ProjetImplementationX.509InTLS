from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sys
sys.path.append("src")
from config.config import PUBLIC_EXPONENT, KEY_SIZE

"""Classe qui implémente les certificats Auto-signés"""
class SelfSignedcertificate:

    def generate_self_signed_certificate(self):
        # Generate la paire de clé RSA
        private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)

        # Définition du sujet et l'émetteur du certificat(auto-signé)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                         'localhost'),
                                      x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                                         "TEST SERVER"),])

        # Creation du certificat x.509
        certificate = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(
            datetime.utcnow())\
        .not_valid_after(
            datetime.utcnow()+
            timedelta(days=365))\
        .sign(private_key, hashes.SHA256())

        # Export de la clé privée et du certificat
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        return private_key_pem, certificate_pem