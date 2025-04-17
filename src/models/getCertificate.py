import sys
sys.path.append("src")
from models.IConnectionManager import IConnectionManager
from models.ICertificateFetcher import ICertificateFetcher
from models.ICertificateRetriever import ICertificateRetriever
from cryptography import x509


class GetCertificate(ICertificateRetriever):
    """Certificate retriever that uses connection manager and fetcher components"""
    
    def __init__(self, connection: IConnectionManager, fetcher: ICertificateFetcher):
        self._connection = connection
        self._fetcher = fetcher

    # Obtient le nom du serveur
    @property
    def connection(self):
        return self._connection

    # Définit un nouveau serveur
    @connection.setter
    def connection(self, newConnection: IConnectionManager):
        self._connection = newConnection

    # Obtient le numéro de port
    @property
    def fetcher(self):
        return self._fetcher

    # Définit un nouveau port pour le serveur
    @fetcher.setter
    def fetcher(self, newFetcher: ICertificateFetcher):
        self._fetcher = newFetcher

    def get_certificate(self, hostname: str, port: int = 443) -> x509.Certificate:
        """Retrieve the x.509 certificate from a remote server.
        
        This implementation uses the connection manager and fetcher components
        to retrieve the certificate.
        
        Args:
            hostname (str): The server hostname
            port (int, optional): The server port. Defaults to 443.
            
        Returns:
            x509.Certificate: The server's certificate
        """
        # Update connection details
        self._connection.hostname = hostname
        self._connection.port = port
        
        # Use fetcher to get certificate
        return self._fetcher.fetchCertificate(hostname, port)
