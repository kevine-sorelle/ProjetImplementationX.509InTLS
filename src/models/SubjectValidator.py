from cryptography import x509
from cryptography.x509.oid import NameOID
from typing import Union, Tuple
from models.certificat import Certificat
from models.ValidatorDeBase import ValidatorDeBase
import sys
sys.path.append("src")
from decorator.decoratorValidator import DecoratorValidator
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class SubjectValidator(DecoratorValidator):
    """Validator for certificate subject fields"""

    def __init__(self, validator_decoree=None):
        """
        Initialize the SubjectValidator.
        
        Args:
            validator_decoree: Optional validator to decorate
        """
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        super().__init__(validator_decoree)
        self.name = "Subject"
    
    def validate(self, certificate: Union[str, x509.Certificate, Certificat]) -> Tuple[bool, str]:
        """Validate the certificate subject fields.
        
        Args:
            certificate: The certificate to validate (string, x509.Certificate, or Certificat)
            
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        # Call the validate method of the decorated object (ValidatorDeBase)
        is_valid, message = self.validator_decoree.validate(certificate)
        if not is_valid:
            return False, message
            
        try:
            # Get the x509 certificate object
            if isinstance(certificate, Certificat):
                x509_cert = certificate.x509_cert
            elif isinstance(certificate, x509.Certificate):
                x509_cert = certificate
            else:
                # Ensure certificate is a valid PEM string before loading
                if isinstance(certificate, str) and "-----BEGIN CERTIFICATE-----" in certificate:
                    x509_cert = x509.load_pem_x509_certificate(certificate.encode())
                else:
                    return False, f"Invalid certificate format: Expected PEM string or x509 object, got {type(certificate)}"

            if not x509_cert:
                 return False, "Could not obtain x509 certificate object for subject validation"
                 
            # Get the subject
            subject = x509_cert.subject
            
            # Check for required subject fields
            cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn:
                return False, "Certificate missing Common Name (CN)"
                
            # Validate Common Name format
            cn_value = cn[0].value
            if not isinstance(cn_value, str):
                return False, f"Invalid Common Name format: {type(cn_value)}"
                
            # Additional checks for organization information if present
            org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if org:
                logger.debug(f"Organization found: {org[0].value}")
                
            # Log successful validation
            logger.debug(f"Subject validation successful for CN: {cn_value}")
            return True, f"Valid subject with CN: {cn_value}"
            
        except Exception as e:
            logger.error(f"Subject validation error: {str(e)}")
            return False, f"Subject validation error: {str(e)}" 