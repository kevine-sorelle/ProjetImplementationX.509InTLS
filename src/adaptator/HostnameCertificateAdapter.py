import logging
import sys
sys.path.append("src")
from adaptator.CertificateAdapter import CertificateAdapter
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate

logger = logging.getLogger(__name__)

class HostnameCertificateAdapter(CertificateAdapter):
    """Adapter for certificates retrieved from hostname"""
    
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.ssl_manager = SSLConnectionManager(hostname, port)
        self.ssl_fetcher = SSLCertificateFetcher()
        self.cert_retriever = GetCertificate(self.ssl_manager, self.ssl_fetcher)
    
    def get_certificate(self):
        """Get certificate from hostname"""
        try:
            return self.cert_retriever.get_certificate(self.hostname, self.port)
        except Exception as e:
            logger.error(f"Error getting certificate from hostname: {str(e)}", exc_info=True)
            raise
    
    def get_source_info(self):
        """Get hostname and port information"""
        return {
            'type': 'hostname',
            'hostname': self.hostname,
            'port': self.port
        }