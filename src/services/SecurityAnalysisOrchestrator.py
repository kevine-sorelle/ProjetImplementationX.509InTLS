from typing import Dict, List, Optional
from services.ServerInfoProvider import ServerInfoProvider
from services.CertificateChainService import CertificateChainService
from services.OCSPChecker import OCSPChecker
from services.SecurityRecommendationGenerator import SecurityRecommendationGenerator
from utils.certificate_parser import CertificateParser
from services.CertificateInfoExtractor import CertificateInfoExtractor
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class SecurityAnalysisOrchestrator:
    def __init__(self):
        self.server_info_provider = ServerInfoProvider()
        self.cert_chain_service = CertificateChainService()
        self.ocsp_checker = OCSPChecker()
        self.recommendation_generator = SecurityRecommendationGenerator()
        self.cert_parser = CertificateParser()

    def analyze_server_security(self, hostname: str, port: int = 443) -> Dict:
        """
        Orchestrate the security analysis of a server.
        
        Args:
            hostname: The hostname to analyze
            port: The port to connect to (default 443)
            
        Returns:
            Dict containing the analysis results
        """
        try:
            # Get server information
            server_info = self.server_info_provider.get_server_info(hostname, port)
            
            # Get and validate certificate chain
            cert_chain, pem_chain, ssl_socket = self.cert_chain_service.get_certificate_chain(hostname, port)
            chain_valid = self.cert_chain_service.validate_chain(cert_chain)
            
            # Count certificates
            total_certs = len(cert_chain)
            valid_certs = sum(1 for cert in cert_chain if self.cert_chain_service.validate_chain([cert]))
            invalid_certs = total_certs - valid_certs
            
            # Add certificate chain information to server_info
            server_info.update({
                'total_certificates': total_certs,
                'valid_certificates': valid_certs,
                'invalid_certificates': invalid_certs
            })
            
            # Extract certificate information
            cert_info = self._extract_certificate_info(cert_chain[0])  # Leaf certificate

            # Get TLS version from SSL socket
            tls_version = ssl_socket.version()
            server_info['tls_version'] = tls_version

            # Merge certificate info with server info
            server_info.update(cert_info)
            
            # Check OCSP status
            ocsp_status = {
                "stapling_supported": OCSPChecker.check_stapling(ssl_socket),
                "details": 'OCSP stapling check completed'
            }
            
            # Generate security recommendations
            security_recommendations = self.recommendation_generator.generate_recommendations(
                server_info,
                cert_info,
                chain_valid,
                ocsp_status
            )

            # Create validation results
            validation_results = {
                'Certificate Chain': {
                    'valid': chain_valid,
                    'message': 'Certificate chain is valid' if chain_valid else 'Certificate chain validation failed'
                },
                'OCSP Status': {
                    'valid': ocsp_status.get('stapling_supported', False),
                    'message': 'OCSP stapling is supported' if ocsp_status.get('stapling_supported', False) else 'OCSP stapling is not supported'
                },
                'Certificate Expiry': {
                    'valid': cert_info.get('days_remaining', 0) > 30,
                    'message': f"Certificate expires in {cert_info.get('days_remaining', 0)} days"
                },
                'TLS Version': {
                    'valid': tls_version in ['TLSv1.2', 'TLSv1.3'],
                    'message': f"Using {tls_version}"
                }
            }
            
            # Compile results
            analysis_results = {
                "server_info": server_info,
                "certificate_info": cert_info,
                "chain_valid": chain_valid,
                "ocsp_status": ocsp_status,
                "security_recommendations": security_recommendations,
                "raw_chain": pem_chain,
                "validation_results": validation_results
            }
            
            return analysis_results

        except Exception as e:
            logger.error(f"Error during security analysis: {str(e)}")
            raise

    def _extract_certificate_info(self, cert) -> Dict:
        """Extract relevant information from a certificate."""
        try:
            info = CertificateInfoExtractor.extract_certificate_info(cert)
            return {
            "subject_cn": info.get("subject_cn", "Unknown"),
            "subject_o": info.get("subject_o", "Unknown"),
            "subject_c": info.get("subject_c", "Unknown"),
            "not_before": info.get("not_before", "Unknown"),
            "not_after": info.get("not_after", "Unknown"),
            "days_remaining": info.get("days_remaining", 0),
            "key_type": info.get("key_type", "Unknown"),
            "key_size": info.get("key_size", 0),
            "signature_algorithm": info.get("signature_algorithm", "Unknown"),
            "serial_number": info.get("serial_number", "Unknown")
            }
        except Exception as e:
            logger.error(f"Error extracting certificate info: {str(e)}")
            return {
            "subject_cn": "Unknown",
            "subject_o": "Unknown",
            "subject_c": "Unknown",
            "not_before": "Unknown",
            "not_after": "Unknown",
            "days_remaining": 0,
            "key_type": "Unknown",
            "key_size": 0,
            "signature_algorithm": "Unknown",
            "serial_number": "Unknown"
        } 