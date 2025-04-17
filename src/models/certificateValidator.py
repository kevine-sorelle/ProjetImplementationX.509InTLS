from abc import ABC, abstractmethod
from cryptography import x509

class ICertificateValidator(ABC):
    @abstractmethod
    def checkCertificateValidity(self, cert: x509.Certificate) -> bool:
        pass