from cryptography import x509
from abc import ABC, abstractmethod


class ICertificateParser(ABC):
    @abstractmethod
    def parse(self, cert_pem: str) -> x509.Certificate:
        pass