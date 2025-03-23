from abc import ABC, abstractmethod

from cryptography import x509
import sys
sys.path.append("src")

"""Interface commune pour toutes les classes de validation"""
class ValidatorInterface(ABC):
    """def __init__(self, name, value, type, certificate):
        self.name = name
        self.value = value
        self.type = type
        self.certificate = certificate"""

    @abstractmethod
    def validate(self, certificate: x509.Certificate):
        pass