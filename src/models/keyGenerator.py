from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime, timedelta

import os

class KeyGenerator:

    def generateECKey(self, key_size: int = 256) -> ec.EllipticCurvePrivateKey:
        """Generate an EC key pair with the specified size"""
        if key_size == 256:
            return ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif key_size == 384:
            return ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif key_size == 521:
            return ec.generate_private_key(ec.SECP521R1(), default_backend())
        else:
            raise ValueError(f"Unsupported EC key size: {key_size}")

    def generateRSAKey(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generate an RSA key pair with the specified size"""
        if key_size not in [512, 1024, 2048, 4096]:
            raise ValueError(f"Unsupported RSA key size: {key_size}")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
