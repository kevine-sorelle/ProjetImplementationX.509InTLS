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
import socket
import ssl
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

@dataclass
class SecurityReport:
    def reset(self) -> None:
        self.__init__()


class SecurityAnalysisStrategy(ABC):
    """Abstract base class defining the interface for security analysis"""
    
    def __init__(self):
        self.cert_info_extractor = CertificateInfoExtractor()
        self.ocsp_checker = OCSPChecker()
        self.recommendation_generator = SecurityRecommendationGenerator()
        self.validation_strategy = ValidationStrategy(['algorithm', 'date', 'key', 'signature', 'extension', 'issuer', 'subject'])
        self.connection_manager = SSLConnectionManager()
        self.certificate_fetcher = SSLCertificateFetcher()

    @abstractmethod
    def analyze_security(self, hostname: str, port: int, certificate: Optional[object] = None) -> Dict:
        """Main method to analyze server security"""
        pass

    def get_connection_info(self, hostname: str, port: int) -> Dict:
        """Common method to get connection info"""
        ssl_socket = None
        try:
            # Create a standard socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create the SSL socket
            sock = socket.create_connection((hostname, port))
            ssl_socket = context.wrap_socket(sock, server_hostname=hostname)
            
            # Get certificate from the connection
            cert = self.connection_manager.get_certificate(hostname, port)
            
            connection_info = {
                'hostname': hostname,
                'port': port,
                'ip_address': socket.gethostbyname(hostname),
                'ssl_socket': ssl_socket,
                'protocol_version': ssl_socket.version(),
                'cipher': ssl_socket.cipher(),
                'certificate': cert
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
            error_msg = f"SSL error occurred: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Error getting connection info: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        finally:
            # Ensure we close the socket if it was created
            if ssl_socket:
                ssl_socket.close()

    def _analyze_certificate_and_connection(self, certificate, connection_info: Dict) -> Dict:
        """Common analysis logic used by all analyzers"""
        # Extract certificate information
        try:
            cert_info = self.cert_info_extractor.extract_certificate_info(certificate)
            logger.debug(f"Certificate info: {cert_info}")
            
            # Check OCSP stapling
            ocsp_status = self.ocsp_checker.check_stapling(connection_info.get('ssl_socket'))
            
            # Validate certificate
            validation_results = self.validation_strategy.validate_certificate(certificate)
            
            # Generate recommendations
            recommendations = self.recommendation_generator.generate_recommendations(
                cert_info=cert_info,
                validation_results=validation_results,
                protocol_version=connection_info.get('protocol_version'),
                cipher=connection_info.get('cipher')
            )

            # Create server info dictionary with default values if None
            server_info = {
                'hostname': connection_info.get('hostname', 'Unknown'),
                'port': connection_info.get('port', 'Unknown'),
                'ip_address': connection_info.get('ip_address', 'Unknown'),
                'tls_version': connection_info.get('protocol_version', 'Unknown'),
                'cipher_suites': [connection_info.get('cipher', ('Unknown',))[0]] if connection_info.get('cipher') else [],
                'ocsp_stapling': ocsp_status
                }
            
            # Add certificate into if available
            if cert_info:
                server_info.update(cert_info)

            return {
                'server_info': server_info,
                'validation_results': validation_results,
                'security_recommendations': recommendations
            }
        except Exception as e:
            logger.error(f"Error in _analyze_certificate_and_connection: {str(e)}")
            return {
                'error': str(e),
                'server_info': None,
                'validation_results': {},
                'security_recommendations': []
            }
    

