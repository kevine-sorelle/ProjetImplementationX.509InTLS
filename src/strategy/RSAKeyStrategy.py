import sys
sys.path.append("src")
from strategy.KeyGenerationStrategy import KeyGenerationStrategy
from cryptography.hazmat.primitives.asymmetric import rsa


class RSAKeyStrategy(KeyGenerationStrategy):
    """Strategy for generating RSA keys"""
    def generate_key(self, key_size: int):
        """Generate RSA key pair with specified key size"""
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        
