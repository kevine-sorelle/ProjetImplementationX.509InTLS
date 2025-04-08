import socket
import ssl
import sys
from typing import Dict, Optional
sys.path.append("src")
from models.certificat import Certificat
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from strategy.SecurityAnalysisStrategy import SecurityAnalysisStrategy
from utils.logger_config import setup_logger
from models.SSLConnectionManager import SSLConnectionManager
from models.SSLCertificateFetcher import SSLCertificateFetcher


# Set up logger for this module
logger = setup_logger(__name__)


class StandardSecurityAnalyzer(SecurityAnalysisStrategy):
    """Analyzes server security using standard connection"""
    
    def __init__(self):
        super().__init__()
        self.connection_manager = SSLConnectionManager()
        self.certificate_fetcher = SSLCertificateFetcher()

    def analyze_security(self, hostname: str, port: int, certificate: Optional[object] = None) -> Dict:
        try:
            # Get connection info
            connection_info = self.get_connection_info(hostname, port)
            
            # Get certificate if not provided
            if not certificate:
                certificate = self.certificate_fetcher.fetchCertificate(hostname, port)
            
            # Use common analysis logic
            return self._analyze_certificate_and_connection(certificate, connection_info)
            
        except Exception as e:
            return self._create_error_response(str(e))

    def get_connection_info(self, hostname: str, port: int):
        self.connection_manager.hostname = hostname
        self.connection_manager.port = port
        try:
            return {
                'ip_address': socket.gethostbyname(hostname),
                'ssl_socket': self.connection_manager.get_ssl_socket(),
                'certificate': self.connection_manager.get_certificate(hostname, port)
            }
        except Exception as e:
            logger.error(f"Error getting connection info: {str(e)}")
            return {}
