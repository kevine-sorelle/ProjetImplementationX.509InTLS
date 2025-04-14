import sys
sys.path.append("src")
from strategy.KeyGenerationStrategy import KeyGenerationStrategy
from cryptography.hazmat.primitives.asymmetric import ec

class ECKeyStrategy(KeyGenerationStrategy):
    """Strategy for generating EC keys"""
    def generate_key(self, key_size: int):
        """Generate EC key pair with specified key size"""
        curve = {
            256: ec.SECP256R1,
            384: ec.SECP384R1,
            521: ec.SECP521R1
        }.get(key_size, ec.SECP256R1())
        return ec.generate_private_key(curve)


