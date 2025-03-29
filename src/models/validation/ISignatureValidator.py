"""Interface for certificate signature validation."""
from abc import ABC, abstractmethod
from typing import Optional
from models.certificat import Certificat

class ISignatureValidator(ABC):
    """Base interface for all signature validators"""
    
    @abstractmethod
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        """Validate a certificate signature
        
        Args:
            cert: Certificate to validate
            issuer_cert: Optional issuer certificate
            
        Returns:
            bool: True if signature is valid
        """
        pass 