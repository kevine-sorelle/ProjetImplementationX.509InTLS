import sys
import ssl
import socket
from cryptography import x509
sys.path.append("src")
from models.IConnectionManager import IConnectionManager
from models.ICertificateRetriever import ICertificateRetriever


class SSLConnectionManager(IConnectionManager, ICertificateRetriever):
    """Handles SSL connection settings and certificate retrieval."""

    def __init__(self, hostname=None, port=None):
        self._hostname = hostname
        self._port = port

    # Obtient le nom du serveur
    @property
    def hostname(self):
        return self._hostname

    # Définit un nouveau serveur
    @hostname.setter
    def hostname(self, newHostname):
        self._hostname = newHostname

    # Obtient le numéro de port
    @property
    def port(self):
        return self._port

    # Définit un nouveau port pour le serveur
    @port.setter
    def port(self, newPort):
        self._port = newPort

    def get_certificate(self, hostname: str, port: int = 443) -> x509.Certificate:
        """Get SSL certificate from a server
        
        This implementation directly uses SSL/TLS connection to retrieve
        the certificate.
        
        Args:
            hostname (str): The server hostname
            port (int, optional): The server port. Defaults to 443.
            
        Returns:
            x509.Certificate: The server's SSL certificate
            
        Raises:
            ValueError: If the hostname is invalid
            ConnectionError: If connection to the server fails
        """
        if not hostname:
            raise ValueError("Hostname is required")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    return x509.load_der_x509_certificate(der_cert)
        except (socket.gaierror, socket.error) as e:
            raise ConnectionError(f"Failed to connect to {hostname}:{port} - {str(e)}")