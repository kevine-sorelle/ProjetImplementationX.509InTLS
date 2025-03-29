from abc import ABC, abstractmethod
from cryptography import x509

class ICertificateRetriever(ABC):
    """Interface for certificate retrieval operations"""
    
    @abstractmethod
    def get_certificate(self, hostname: str, port: int = 443) -> x509.Certificate:
        """Retrieve an X.509 certificate from a server
        
        Args:
            hostname (str): The server hostname
            port (int, optional): The server port. Defaults to 443.
            
        Returns:
            x509.Certificate: The server's certificate
            
        Raises:
            ValueError: If the hostname is invalid or connection fails
        """
        pass 