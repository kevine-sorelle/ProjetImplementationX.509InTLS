"""Base validator class for certificate validation."""
from cryptography import x509
from utils.logger_config import setup_logger
from typing import Union, Tuple

logger = setup_logger(__name__)

class ValidatorDeBase:
    """Base validator class that all other validators can build upon"""

    def validate(self, certificate: Union[str, x509.Certificate]) -> Tuple[bool, str]:
        """Basic validation to ensure we have a valid X.509 certificate.
        
        Args:
            certificate: The certificate to validate (string or x509.Certificate)
            
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        try:
            # If it's already an x509.Certificate object, it's valid
            if isinstance(certificate, x509.Certificate):
                return True, "Valid X.509 certificate format"
                
            # If it's a string, try to parse it
            if isinstance(certificate, str):
                try:
                    x509.load_pem_x509_certificate(certificate.encode())
                    return True, "Valid X.509 certificate format"
                except Exception as e:
                    return False, f"Invalid PEM format: {str(e)}"
                    
            return False, f"Unsupported certificate type: {type(certificate)}"
            
        except Exception as e:
            logger.error(f"Base validation error: {str(e)}")
            return False, f"Base validation error: {str(e)}"