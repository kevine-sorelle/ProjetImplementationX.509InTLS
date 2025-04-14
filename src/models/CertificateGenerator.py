from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
from models.KEM import KEM
from models.keyGenerator import KeyGenerator

class KeyGenerationStrategy(ABC):
    """Abstract base class for key generation strategies"""
    
    @abstractmethod
    def generate_key(self, key_size: int):
        """Generate a key pair of the specified size"""
        pass

class RSAKeyStrategy(KeyGenerationStrategy):
    """Strategy for generating RSA keys"""
    
    def generate_key(self, key_size: int):
        """Generate an RSA key pair"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

class ECKeyStrategy(KeyGenerationStrategy):
    """Strategy for generating EC keys"""
    
    def generate_key(self, key_size: int):
        """Generate an EC key pair"""
        curve = {
            256: ec.SECP256R1(),
            384: ec.SECP384R1(),
            521: ec.SECP521R1()
        }.get(key_size, ec.SECP256R1())
        
        return ec.generate_private_key(curve)

