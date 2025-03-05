from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append("src")
from models.ICertificateMetadata import ICertificateMetadata


class CertificateMetadata(ICertificateMetadata):
    """Implémentation de récupération de l'émetteur du certificat"""
    def getIssuer(self, cert: str) -> str:
        print(f"this is the getIssuer certificate {cert}")
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        return cert.issuer.rfc4514_string()

    # Méthode de validation pour l'émetteur
    def validateIssuer(self, cert: str, expected_parts: dict) -> bool:
        issuer = self.getIssuer(cert)
        # Vérifie si toutes les paires clé-valeur sont présent dans l'émetteur
        for key, value in expected_parts.items():
            if f"{key}={value}" not in issuer:
                return False
        return True

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