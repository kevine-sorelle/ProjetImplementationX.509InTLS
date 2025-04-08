from abc import ABC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Union, Tuple
import sys
sys.path.append("src")
from models.decoratorValidador import DecoratorValidador
from models.certificat import Certificat
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class IssuerValidator(DecoratorValidador):
    """def __init__(self, name, value, type, certificate, validation_rules=None):
        super().__init__(name, value, type, certificate)
        self.validation_rules = validation_rules if validation_rules else {}"""


    def __init__(self, validator_decoree: DecoratorValidador):
        super().__init__(validator_decoree)


    def validate(self, cert: Union[x509.Certificate, str, Certificat]) -> Tuple[bool, str]:
        try:
            certificat_validee = self._validate_issuer(cert)
            if self.validator_decoree and self.validator_decoree.validate(cert):
                return certificat_validee
            else:
                return certificat_validee
        except Exception as e:
            logger.error(f"Issuer validation error: {str(e)}")
            return False, f"Issuer validation error: {str(e)}"

    def _validate_issuer(self, cert: Union[x509.Certificate, str, Certificat]) -> Tuple[bool, str]:
        try:
            # Handle string certificates
            if isinstance(cert, str):
                cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            
            # Get the issuer based on certificate type
            if isinstance(cert, Certificat):
                issuer = cert.get_issuer_name()
                if not issuer:
                    return False, "Certificate has no issuer information"
            else:
                # For x509.Certificate objects
                issuer = cert.issuer.rfc4514_string()
            
            logger.debug(f"Issuer: {issuer}")
            
            # Validate issuer format
            expected_parts = issuer.split(",")
            for part in expected_parts:
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                if f"{key}={value}" not in issuer:
                    return False, f"Issuer validation failed: {key}={value} not found in issuer string"
            
            return True, f"Issuer validation successful: {issuer}"
                
        except Exception as e:
            logger.error(f"Error validating issuer: {str(e)}")
            return False, f"Error validating issuer: {str(e)}"

    def getIssuer(self, cert: Union[x509.Certificate, str, Certificat]) -> str:
        try:
            # Handle string certificates
            if isinstance(cert, str):
                cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            
            # Get the issuer based on certificate type
            if isinstance(cert, Certificat):
                return cert.get_issuer_name()
            else:
                # For x509.Certificate objects
                return cert.issuer.rfc4514_string()
        except Exception as e:
            logger.error(f"Error getting issuer: {str(e)}")
            return f"Error: {str(e)}"