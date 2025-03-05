from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from abc import ABC, abstractmethod
import sys
sys.path.append("src")
from models.certificateValidor import ICertificateValidator


class DateValidator(ICertificateValidator):
    """Checks if the certificate is within the valid date range"""
    def checkCertificateValidity(self, cert: x509.Certificate) -> bool:
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        print(f"cert.not_valid_before.tzinfo:{cert.not_valid_before_utc.tzinfo}")
        print(f"cert.not_valid_after.tzinfo:{cert.not_valid_after_utc.tzinfo}")
        print(f"datetime.now(timezone.utc).tzinfo:{datetime.now(timezone.utc).tzinfo}")
        return cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc