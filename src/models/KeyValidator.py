from cryptography import x509
from cryptography.hazmat.backends import default_backend

import sys
sys.path.append("src")
from models.decoratorValidador import DecoratorValidador


class KeyValidator(DecoratorValidador):
    """def __init__(self, name, value, type, certificate):
        super().__init__(name, value, type, certificate)"""

    def validate(self, cert: x509.Certificate):
        if isinstance(cert, str):
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        # Récupération de la taille de la clé de l'objet certificat
        key_length = cert.public_key().key_size
        # définition de la taille de clé minimale acceptée
        MIN_RSA_KEY_SIZE = 2048
        MIN_EC_KEY_SIZE = 256
        MIN_DSA_KEY_SIZE = 1024
        # Effectuer la validation
        if key_length >= MIN_RSA_KEY_SIZE or key_length >= MIN_EC_KEY_SIZE or key_length >= MIN_DSA_KEY_SIZE:
            return True, "Key size is valid"
        else:
            return False, "Key size is invalid"

