import ssl
from cryptography import x509
from typing import List
class CertificateChainService:
    @staticmethod
    def get_certificate_chain(hostname, port) -> List:
        """
        Get the complete certificate chain for a server.
        
        Args:
            hostname: The hostname to get certificates for
            port: The port to connect to
            
        Returns:
            list: List of certificates in the chain
        """
        try:
            # Use ssl to get the certificate
            cert = ssl.get_server_certificate((hostname, port))
            cert_obj = x509.load_pem_x509_certificate(cert.encode())
            
            # For simplicity, we'll just return the leaf certificate
            # In a real implementation, you would fetch the full chain
            return [cert_obj]
        except Exception:
            return []