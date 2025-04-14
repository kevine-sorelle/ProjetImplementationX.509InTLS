from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging
import sys
sys.path.append("src")
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate

logger = logging.getLogger(__name__)

class CertificateAdapter(ABC):
    """Abstract base class for certificate adapters"""
    
    @abstractmethod
    def get_certificate(self):
        """Get the certificate in PEM format"""
        pass
    
    @abstractmethod
    def get_source_info(self):
        """Get information about the certificate source"""
        pass


