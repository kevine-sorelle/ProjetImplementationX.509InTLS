from abc import ABC, abstractmethod
from typing import Optional, Union
from cryptography import x509
import sys
sys.path.append("src")
from models.certificat import Certificat

class SignatureStrategy(ABC ):
    @abstractmethod
    def validate_signature(self, cert: Union[Certificat, str, x509.Certificate], issuer_cert: Optional[Certificat] = None) -> bool:
        pass


