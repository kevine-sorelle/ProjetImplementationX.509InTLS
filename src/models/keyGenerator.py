from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime, timedelta

import os

class KeyGenerator:


    def generateECKey(self, key_size: int = 256) -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
