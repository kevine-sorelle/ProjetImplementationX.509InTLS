import socket
import ssl
import sys
sys.path.append("src")
from strategy.SecurityAnalysisStrategy import SecurityAnalysisStrategy
from models.certificat import Certificat
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils.logger_config import setup_logger
from typing import Dict

# Set up logger for this module
logger = setup_logger(__name__)


class CertificateBasedAnalyzer(SecurityAnalysisStrategy):
    def __init__(self):
        super().__init__()

    def analyze_security(self, hostname: str, port: int, certificate: object) -> Dict:
        try:
            if not certificate:
                raise ValueError("Certificate is required for CertificateBasedAnalyzer")

            # Get connection info using SSLConnectionManager
            connection_info = self.get_connection_info(hostname, port)
            if not connection_info:
                raise ValueError("Could not establish connection to server")

            return self._analyze_certificate_and_connection(certificate, connection_info)

        except Exception as e:
            logger.error(f"Error in analyze_security: {str(e)}")
            return self._create_error_response(str(e))

   

    def _create_error_response(self, error_message: str) -> Dict:
        return {
            'error': error_message,
            'server_info': None,
            'validation_results': {},
            'security_recommendations': []
        }

