from abc import ABC

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from src.models.Validator import Validator
from src.models.certificateValidator import ICertificateValidator


class IssuerValidator(Validator):
    def __init__(self, name, value, type, certificate, validation_rules=None):
        super().__init__(name, value, type, certificate)
        self.validation_rules = validation_rules if validation_rules else {}

    def validate(self):
        cert = self.certificate
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        issuer = cert.issuer.rfc4514_string()
        expected_parts = self.value.split(",")
        for part in expected_parts:
            key, value = part.split("=")
            if f"{key}={value}" not in issuer:
                return False, f"Issuer does not contain {key}={value}"
        return True, "Issuer is valid"