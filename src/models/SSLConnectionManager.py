import sys
import ssl
import socket
from cryptography import x509
sys.path.append("src")
from models.IConnectionManager import IConnectionManager
from models.ICertificateRetriever import ICertificateRetriever
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

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
        
    def get_certificate_chain_pem(self, hostname: str, port: int = 443) -> str:
        """Get the full certificate chain from a server in PEM format.
        
        Args:
            hostname (str): The server hostname
            port (int, optional): The server port. Defaults to 443.
            
        Returns:
            str: The certificate chain in PEM format (may contain multiple certificates).
            
        Raises:
            ValueError: If the hostname is invalid
            ConnectionError: If connection to the server fails or no certificate is returned.
        """
        if not hostname:
            raise ValueError("Hostname is required")
        
        logger.debug(f"Fetching certificate chain PEM for {hostname}:{port}")
        try:
            # Note: get_server_certificate doesn't verify the certificate chain itself
            pem_cert_chain = ssl.get_server_certificate((hostname, port))
            if not pem_cert_chain:
                raise ConnectionError(f"No certificate chain received from {hostname}:{port}")
            logger.debug(f"Successfully fetched PEM chain (length: {len(pem_cert_chain)})")
            return pem_cert_chain
        except (socket.gaierror, socket.error, ssl.SSLError, OSError) as e:
            logger.error(f"Failed to get certificate chain PEM from {hostname}:{port} - {str(e)}")
            raise ConnectionError(f"Failed to get certificate chain PEM from {hostname}:{port} - {str(e)}")

    def get_certificate(self, hostname: str, port: int = 443) -> x509.Certificate:
        """Get SSL *end-entity* certificate from a server.
        
        Note: This method typically only returns the first certificate, not the chain.
        Consider using get_certificate_chain_pem for full chain analysis.
        
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

        logger.debug(f"Fetching end-entity certificate object for {hostname}:{port}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                # Disable hostname checking and verification for getpeercert to work more reliably
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        raise ConnectionError(f"No peer certificate received from {hostname}:{port}")
                    logger.debug("Successfully fetched end-entity certificate object")
                    return x509.load_der_x509_certificate(der_cert)
        except (socket.gaierror, socket.error, ssl.SSLError, OSError) as e:
            logger.error(f"Failed to connect or get certificate object from {hostname}:{port} - {str(e)}")
            raise ConnectionError(f"Failed to connect or get certificate object from {hostname}:{port} - {str(e)}")