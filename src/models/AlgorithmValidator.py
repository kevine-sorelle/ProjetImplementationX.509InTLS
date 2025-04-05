from typing import Union, Tuple
from cryptography import x509
import sys
sys.path.append("src")
from  config import DEPRECATED_ALGORITHMS, SECURE_ALGORITHMS
from .decoratorValidador import DecoratorValidador
from .certificat import Certificat
from .ValidatorDeBase import ValidatorDeBase
from cryptography.hazmat.primitives.asymmetric import rsa

class AlgorithmValidator(DecoratorValidador):
    """
    Validator that checks if the certificate's signature algorithm is secure.
    Implements the Decorator pattern to add algorithm validation to other validators.
    """


    def __init__(self, validator_decoree=None):
        """
        Initialize the AlgorithmValidator.
        
        Args:
            validator_decoree: Optional validator to decorate
        """
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        super().__init__(validator_decoree)
        self.name = "Algorithm"

    def validate(self, certificate: Union[Certificat, str, x509.Certificate]) -> Tuple[bool, str]:
        """
        Validate the certificate's signature algorithm.
        
        Args:
            certificate: The certificate to validate (Certificat object, PEM string, or x509.Certificate)
            
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        # First validate using the decorated validator if it exists
        if self.validator_decoree:
            is_valid, message = self.validator_decoree.validate(certificate)
            if not is_valid:
                return False, f"Previous validation failed: {message}"

        # Convert certificate to x509.Certificate if needed
        if isinstance(certificate, str):
            try:
                cert = x509.load_pem_x509_certificate(certificate.encode())
            except ValueError:
                return False, "Invalid PEM certificate format"
        elif isinstance(certificate, Certificat):
            cert = certificate.cert
        else:
            cert = certificate

        # Get the signature algorithm
        sig_algorithm = cert.signature_algorithm_oid
        sig_algorithm_name = self._get_algorithm_name(sig_algorithm)

        # Check if algorithm is in deprecated list
        for deprecated, details in DEPRECATED_ALGORITHMS.items():
            if deprecated in sig_algorithm_name:
                if isinstance(details, dict):
                    # For RSA, check key size
                    if deprecated == 'RSA':
                        try:
                            key_size = cert.public_key().key_size
                            if key_size < details['min_key_size']:
                                return False, details['message']
                        except AttributeError:
                            return False, "Could not determine RSA key size"
                else:
                    return False, details

        # Check if algorithm is in secure list
        for secure_algo, requirements in SECURE_ALGORITHMS.items():
            if secure_algo in sig_algorithm_name:
                # For RSA, verify key size and hash
                if secure_algo == 'RSA':
                    try:
                        public_key = cert.public_key()
                        if isinstance(public_key, rsa.RSAPublicKey):
                            key_size = public_key.key_size
                            if key_size < requirements['min_key_size']:
                                return False, f"RSA key size {key_size} is below minimum secure size of {requirements['min_key_size']}"
                        else:
                            return False, "Could not determine RSA key size"
                        
                        
                        # Check hash algorithm
                        hash_algo = sig_algorithm_name.split('With')[1].lower() if 'With' in sig_algorithm_name else None
                        if hash_algo and hash_algo not in requirements['secure_hashes']:
                            return False, f"Hash algorithm {hash_algo} is not considered secure for RSA"
                    except AttributeError:
                        return False, "Could not determine RSA key size"
                
                # For ECDSA, verify curve and hash
                elif secure_algo == 'ECDSA':
                    try:
                        curve = cert.public_key().curve.name
                        if curve not in requirements['secure_curves']:
                            return False, f"ECDSA curve {curve} is not considered secure"
                        
                        # Check hash algorithm
                        lower_sig_algorithm_name = sig_algorithm_name.lower()
                        if 'with' in lower_sig_algorithm_name:
                            hash_algo = lower_sig_algorithm_name.split('with')[1]
                        else:
                            hash_algo = None
                        if hash_algo and hash_algo not in requirements['secure_hashes']:
                            return False, f"Hash algorithm {hash_algo} is not considered secure for ECDSA"
                    except AttributeError:
                        return False, "Could not determine ECDSA curve"
                
                # For Ed25519 and Ed448, no additional checks needed
                return True, f"Algorithm {sig_algorithm_name} is considered secure"

        # If we get here, the algorithm wasn't found in either list
        return False, f"Unknown or unsupported algorithm: {sig_algorithm_name}"
        
    def _get_algorithm_name(self, oid) -> str:
        """
        Convert an OID to a human-readable algorithm name.
        
        Args:
            oid: The ObjectIdentifier from the certificate
            
        Returns:
            str: A string algorithm name
        """
        # The ObjectIdentifier class in cryptography has a 'name' attribute
        # that contains a human-readable name like 'ecdsa-with-SHA256'
        name = oid._name if hasattr(oid, "_name") else oid.dotted_string

        if 'ecdsa' in name.lower():
            return 'ECDSAwith' + name.split('-')[-1].upper()  # e.g., "ecdsa-with-SHA256" → "ECDSAwithSHA256"
        elif 'rsa' in name.lower():
            return 'RSAwith' + name.split('-')[-1].upper()
        else:
            return name  # fallback to raw name if pattern is unknown
