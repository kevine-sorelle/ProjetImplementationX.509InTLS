import sys
sys.path.append("src")
from services.CertificateChainService import CertificateChainService
from strategy.SecurityAnalysisStrategy import SecurityAnalysisStrategy
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils.logger_config import setup_logger
from typing import Dict, Optional

# Set up logger for this module
logger = setup_logger(__name__)


class CertificateBasedAnalyzer(SecurityAnalysisStrategy):
    def __init__(self):
        super().__init__()
        self.cert_chain_service = CertificateChainService()

    def analyze_security(self, hostname: str, port: int, certificate: object) -> Dict:
        try:
            self._validate_inputs(hostname, port, certificate)

            # Get certificate chain
            cert_chain, chain_pem, ssl_socket = self.cert_chain_service.get_certificate_chain(hostname, port)

            # Validate certificate chain
            is_valid_chain = self.cert_chain_service.validate_chain(cert_chain)

            standard_analysis = self.security_analysis_orchestrator.analyze_server_security(hostname, port)

            # Add chain analysis to results
            return {
                **standard_analysis,
                'certificate_chain': {
                    'valid': is_valid_chain,
                    'length': len(cert_chain),
                    'pem_chain': chain_pem
                }
            }

        except Exception as e:
            logger.error(f"Error in analyze_security: {str(e)}")
            return self._create_error_response(str(e))
        finally:
            if ssl_socket in locals():
                ssl_socket.close()

    def _validate_inputs(self, hostname: str, port: int, certificate: Optional[object] = None):
        if not hostname:
            raise ValueError("Hostname is required")
        if not port:
            raise ValueError("Port is required")
        if not certificate:
            raise ValueError("Certificate is required")


    def _create_error_response(self, error_message: str) -> Dict:
        return {
            'error': error_message,
            'server_info': None,
            'validation_results': {},
            'security_recommendations': []
        }

