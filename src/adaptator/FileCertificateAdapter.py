import sys
sys.path.append("src")
from adaptator.CertificateAdapter import CertificateAdapter
import logging
from cryptography import x509

logger = logging.getLogger(__name__)

class FileCertificateAdapter(CertificateAdapter):
    """Adapter for certificates loaded from file"""
    
    def __init__(self, certificate_file):
        """Initialize with certificate file path
        
        Args:
            certificate_file_path (str): Path to the certificate file
        """
        self.certificate_file = certificate_file
    
    def get_certificate(self) -> x509.Certificate:
        """Get certificate from file
        Returns:
            x509.Certificate: The loaded certificate
            
        Raises:
            Exception: If there's an error reading or parsing the certificate
        """
        try:
            return self.certificate_file.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Error reading certificate file: {str(e)}", exc_info=True)
            raise
    
    def get_source_info(self):
        """Get file information"""
        return {
            'type': 'file',
            'filename': self.certificate_file.filename
        }