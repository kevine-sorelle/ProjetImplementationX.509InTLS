from abc import ABC, abstractmethod

class ICertificateFetcher(ABC):
    """Interface pour recupérer les certificats d'un serveur distant."""

    @abstractmethod
    def fetchCertificate(self, hostname: str, port: int) -> str:
        pass