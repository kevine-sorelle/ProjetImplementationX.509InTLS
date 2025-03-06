from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
import os
import sys
sys.path.append("src")
from models.keyGenerator import KeyGenerator

class KEM:
    """Gestion des clés de chiffrement et de déchiffrement"""

    @staticmethod
    def encapsulate():
        return os.urandom(32) # 256-bit shared secret

    def decapsulate(self, shared_secret: bytes):
        return shared_secret