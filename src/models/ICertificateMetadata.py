from abc import ABC, abstractmethod
from cryptography import x509

class ICertificateMetadata(ABC):
    """Classe abstraite pour extraire les données d'un certificat"""
    @abstractmethod
    def getIssuer(self, cert: x509.Certificate) -> str:
        pass

    @abstractmethod
    def getValidityPeriod(self, cert: x509.Certificate) -> dict:
        pass