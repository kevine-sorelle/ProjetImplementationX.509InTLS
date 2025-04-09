from abc import ABC, abstractmethod
from dataclasses import dataclass
import sys
sys.path.append("src")
from services.CertificateInfoExtractor import CertificateInfoExtractor
from services.OCSPChecker import OCSPChecker
from services.SecurityRecommendationGenerator import SecurityRecommendationGenerator
from typing import List, Dict, Optional
from models.ValidationStrategy import ValidationStrategy
from models.SSLConnectionManager import SSLConnectionManager
from models.SSLCertificateFetcher import SSLCertificateFetcher
from utils.certificate_parser import CertificateParser
import socket
import ssl
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

class SecurityAnalysisStrategy(ABC):
    """Abstract base class defining the interface for security analysis"""
    
    def __init__(self):
        self.cert_info_extractor = CertificateInfoExtractor()
        self.ocsp_checker = OCSPChecker()
        self.recommendation_generator = SecurityRecommendationGenerator()
        self.validation_strategy = ValidationStrategy(['algorithm', 'date', 'key', 'signature', 'extension', 'issuer', 'subject'])
        self.connection_manager = SSLConnectionManager()
        self.certificate_fetcher = SSLCertificateFetcher()
        self.certificate_parser = CertificateParser()

    @abstractmethod
    def analyze_security(self, hostname: str, port: int, certificate: Optional[object] = None) -> Dict:
        """Main method to analyze server security"""
        pass

    def get_connection_info(self, hostname: str, port: int) -> Dict:
        """Common method to get connection info, including the certificate chain PEM."""
        ssl_socket = None
        cert_chain_pem = None
        end_entity_cert = None
        try:
            # Create a standard socket
            context = ssl.create_default_context()
            
            # Fetch PEM chain first
            try:
                cert_chain_pem = self.connection_manager.get_certificate_chain_pem(hostname, port)
                # Parse the chain to get the first cert (end-entity)
                parsed_chain = self.certificate_parser.parse_pem_chain(cert_chain_pem)
                if parsed_chain:
                    end_entity_cert = parsed_chain[0]
                else:
                    logger.warning(f"Could not parse any certificates from the PEM chain for {hostname}:{port}")
            except ConnectionError as e:
                logger.error(f"Failed to fetch PEM chain: {e}")
                # Optionally, try fetching just the single cert as a fallback
                # end_entity_cert = self.connection_manager.get_certificate(hostname, port)
            
            # Create the SSL socket for other info (protocol, cipher)
            # We need to establish a connection again for this, unfortunately
            context.check_hostname = False # Keep settings from previous attempt
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((hostname, port))
            ssl_socket = context.wrap_socket(sock, server_hostname=hostname)
            
            connection_info = {
                'hostname': hostname,
                'port': port,
                'ip_address': socket.gethostbyname(hostname),
                'ssl_socket': ssl_socket, # Note: This socket is temporary for info, will be closed
                'protocol_version': ssl_socket.version(),
                'cipher': ssl_socket.cipher(),
                'certificate_chain_pem': cert_chain_pem, # Store the PEM chain
                'certificate': end_entity_cert # Store the parsed end-entity cert object
            }
            return connection_info
            
        except socket.gaierror as e:
            error_msg = f"DNS lookup failed for {hostname}: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        except socket.error as e:
            error_msg = f"Connection failed to {hostname}:{port}: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        except ssl.SSLError as e:
            error_msg = f"SSL error occurred during connection info gathering: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Error getting connection info: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise Exception(error_msg)
        finally:
            # Ensure we close the temporary socket if it was created
            if ssl_socket:
                ssl_socket.close()

    def _analyze_certificate_and_connection(self, certificate, connection_info: Dict) -> Dict:
        """Common analysis logic. Now receives the parsed end-entity certificate.
           Needs further modification for full chain analysis.
        """
        
        # The 'certificate' argument passed here should now be the parsed end-entity cert object
        end_entity_certificate = certificate 
        pem_chain_str = connection_info.get('certificate_chain_pem')
        parsed_chain = self.certificate_parser.parse_pem_chain(pem_chain_str) if pem_chain_str else []

        # --- TODO: Implement Chain Validation Logic --- 
        # This is where you'd add code to validate the parsed_chain
        # For now, we'll just count them.
        total_certs = len(parsed_chain)
        valid_certs = 0 # Placeholder
        invalid_certs = 0 # Placeholder
        # --- End TODO ---
        
        # Extract certificate information (from end-entity cert)
        try:
            cert_info = self.cert_info_extractor.extract_certificate_info(end_entity_certificate)
            logger.debug(f"End-entity certificate info: {cert_info}")
            
            # Check OCSP stapling (still uses a temporary socket, might need rethink)
            # For now, we pass None as the socket isn't persistent from get_connection_info
            ocsp_status = self.ocsp_checker.check_stapling(None) 
            
            # Validate *end-entity* certificate using existing strategy
            validation_results = self.validation_strategy.validate_certificate(end_entity_certificate)
            
            # Generate recommendations (based on end-entity cert for now)
            recommendations = self.recommendation_generator.generate_recommendations(
                cert_info=cert_info,
                validation_results=validation_results,
                protocol_version=connection_info.get('protocol_version'),
                cipher=connection_info.get('cipher')
            )

            # Create server info dictionary
            server_info = {
                'hostname': connection_info.get('hostname', 'Unknown'),
                'port': connection_info.get('port', 'Unknown'),
                'ip_address': connection_info.get('ip_address', 'Unknown'),
                'tls_version': connection_info.get('protocol_version', 'Unknown'),
                'cipher_suites': [connection_info.get('cipher', ('Unknown',))[0]] if connection_info.get('cipher') else [],
                'ocsp_stapling': ocsp_status,
                # Add chain counts (use keys expected by template)
                'total_certificates': total_certs, 
                'valid_certificates': valid_certs, 
                'invalid_certificates': invalid_certs
                }
            
            # Add certificate info if available
            if cert_info:
                server_info.update(cert_info)

            return {
                'server_info': server_info,
                'validation_results': validation_results, # Validation of end-entity cert
                'security_recommendations': recommendations
            }
        except Exception as e:
            logger.error(f"Error in _analyze_certificate_and_connection: {str(e)}", exc_info=True)
            # Ensure chain counts are still returned even on error (use keys expected by template)
            return {
                'error': str(e),
                'server_info': {
                    'total_certificates': total_certs,
                    'valid_certificates': valid_certs,
                    'invalid_certificates': invalid_certs
                 },
                'validation_results': {},
                'security_recommendations': []
            }
    

