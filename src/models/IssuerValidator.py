from abc import ABC

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append("src")
from models.decoratorValidador import DecoratorValidador


class IssuerValidator(DecoratorValidador):
    """def __init__(self, name, value, type, certificate, validation_rules=None):
        super().__init__(name, value, type, certificate)
        self.validation_rules = validation_rules if validation_rules else {}"""


    def __init__(self, validator_decoree: DecoratorValidador):
        super().__init__(validator_decoree)


    def validate(self, cert: x509.Certificate):
        certificat_validee = self._validate_issuer(cert)
        if self.validator_decoree and self.validator_decoree.validate(cert):
            return certificat_validee
        else:
            return certificat_validee

    def _validate_issuer(self, cert: x509.Certificate):
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        issuer = cert.issuer.rfc4514_string()
        expected_parts = issuer.split(",")
        for part in expected_parts:
            key, value = part.split("=")
            if f"{key}={value}" not in issuer:
                return False
        return True

    def getIssuer(self, cert: x509.Certificate) -> str:
        print(f"this is the getIssuer certificate {cert}")
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        return cert.issuer.rfc4514_string()