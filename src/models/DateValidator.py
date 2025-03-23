from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from abc import ABC, abstractmethod
import sys
sys.path.append("src")
from models.decoratorValidador import DecoratorValidador


class DateValidator(DecoratorValidador):
    """def __init__(self, name, value, type, certificate):
        super().__init__(name, value, type, certificate)"""
    def __init__(self, validator_decoree: DecoratorValidador):
        super().__init__(validator_decoree)


    def validate(self, cert: x509.Certificate):
        certificat_validee = self._validate_date(cert)
        if self.validator_decoree and self.validator_decoree.validate(cert):
            return certificat_validee, "Date is valid"
        else:
            return certificat_validee, "Date is invalid"

    """Vérifie si le certificat est valide pour la date actuelle"""
    def _validate_date(self, cert: x509.Certificate) -> bool:
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        print(f"cert.not_valid_before.tzinfo:{cert.not_valid_before_utc.tzinfo}")
        print(f"cert.not_valid_after.tzinfo:{cert.not_valid_after_utc.tzinfo}")
        print(f"datetime.now(timezone.utc).tzinfo:{datetime.now(timezone.utc).tzinfo}")
        return cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc

    # Méthode de vérification de la période de validité
    def getValidityPeriod(self, cert: x509.Certificate) -> dict:
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        # Get the validity period
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        return {
            "valid_from": valid_from,
            "valid_to": valid_to
        }