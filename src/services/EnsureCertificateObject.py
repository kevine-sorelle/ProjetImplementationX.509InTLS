from typing import Optional, Union
from cryptography import x509
import sys
sys.path.append("src")
from models.certificat import Certificat
from utils.logger_config import setup_logger
from cryptography.hazmat.backends import default_backend
# Set up logger for this module
logger = setup_logger(__name__)

class EnsureCertificateObject:

    @staticmethod
    def ensure_certificate_object(certificate: Union[Certificat, str, x509.Certificate]) -> Optional[x509.Certificate]:
        """Convert input to x509.Certificate object if needed"""
        try:   
            if isinstance(certificate, str):
                # Convert PEM string to x509.Certificate
                x509_cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
                return x509_cert
            elif isinstance(certificate, Certificat):
                return certificate.x509_cert
            elif isinstance(certificate, x509.Certificate):
                return certificate
            logger.error(f"Unsupported certificate type: {type(certificate)}")  
            return None
        except Exception as e:
            logger.error(f"Error converting certificate: {str(e)}")
            return None