from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Union, Tuple
import sys
sys.path.append("src")
from decorator.decoratorValidator import DecoratorValidator
from models.certificat import Certificat
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class KeyValidator(DecoratorValidator):
    def __init__(self, validator_decoree: DecoratorValidator):
        super().__init__(validator_decoree)

    def validate(self, cert: Union[x509.Certificate, str, Certificat]) -> Tuple[bool, str]:
        try:
            # Handle string certificates
            if isinstance(cert, str):
                cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            
            # Get the public key based on certificate type
            if isinstance(cert, Certificat):
                public_key = cert.get_public_key()
                if public_key is None:
                    return False, "Certificate has no public key"
            else:
                # For x509.Certificate objects
                public_key = cert.public_key()
            
            # Get the key size
            key_length = public_key.key_size
            logger.debug(f"Key size: {key_length} bits")
            
            # Definition of minimum key sizes
            MIN_RSA_KEY_SIZE = 2048
            MIN_EC_KEY_SIZE = 256
            MIN_DSA_KEY_SIZE = 1024
            
            # Perform validation
            if key_length >= MIN_RSA_KEY_SIZE or key_length >= MIN_EC_KEY_SIZE or key_length >= MIN_DSA_KEY_SIZE:
                return True, f"Key size is valid ({key_length} bits)"
            else:
                return False, f"Key size is invalid ({key_length} bits, minimum required: RSA={MIN_RSA_KEY_SIZE}, EC={MIN_EC_KEY_SIZE}, DSA={MIN_DSA_KEY_SIZE})"
                
        except Exception as e:
            logger.error(f"Key validation error: {str(e)}")
            return False, f"Key validation error: {str(e)}"

