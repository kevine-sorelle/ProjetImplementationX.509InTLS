from cryptography import x509
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append("src")
from config import TRUSTED_ISSUERS
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from models.decoratorValidador import DecoratorValidador


class SignatureValidator(DecoratorValidador):
    """def __init__(self, name, value, type, certificate):
        super().__init__(self, name, value, type, certificate)"""
    def __init__(self, validator_decoree):
        super().__init__(validator_decoree)

    def validate(self, certificate: x509.Certificate):
        signature_validee = self._validate_signature(certificate)
        if self.validator_decoree and self.validator_decoree.validate(certificate):
            return signature_validee, "Signature is valid"
        else:
            return signature_validee, "Signature is invalid"

    def _validate_signature(self, certificate: x509.Certificate):
        """Validate the signature of the certificate"""
        if isinstance(certificate, str):
            certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

        # Vérification de la signature
        is_signature_valid = self.verify_certificate_signature(certificate)
        if not is_signature_valid:
            return False

        # Vérification de l'émetteur
        is_issuer_valid = self.validate_trusted_issuer(certificate, TRUSTED_ISSUERS)
        if not is_issuer_valid:
            return False

        return True


    def get_public_key(self, certificate: x509.Certificate):
        """Extract the public key from the certificate"""
        return certificate.public_key()

    def get_signature(self, certificate: x509.Certificate):
        """Extract the signature from the certificate"""
        return certificate.signature

    def verify_certificate_signature(self, cert: x509.Certificate):
        """Verify the signature of the certificate"""
        public_key = self.get_public_key(cert)
        signature = self.get_signature(cert)
        try:
            # Gestion des signatures RSA
            if isinstance(public_key, rsa.RSAPublicKey):
                return public_key.verify(signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            # Gestion des signatures ECDSA
            elif isinstance(public_key, EllipticCurvePublicKey):
                return public_key.verify(
                    signature,
                    cert.tbs_certificate_bytes,
                    ECDSA(cert.signature_hash_algorithm))
            else:
                raise ValueError("Type algorithme de signature inconnu")
        except InvalidSignature:
            return False

    def validate_trusted_issuer(self, certificate: x509.Certificate, trusted_issuer: list):
        """Validate the issuer against a trusted issuers list."""
        actual_issuer = certificate.issuer.rfc4514_string()
        return any(trusted_issuer in actual_issuer for trusted_issuer in trusted_issuer)

