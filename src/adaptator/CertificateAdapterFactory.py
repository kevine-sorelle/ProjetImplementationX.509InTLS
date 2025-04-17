import sys
sys.path.append("src")
from src.adaptator.FileCertificateAdapter import FileCertificateAdapter
from src.adaptator.HostnameCertificateAdapter import HostnameCertificateAdapter


class CertificateAdapterFactory:
    """Factory for creating certificate adapters"""
    
    @staticmethod
    def create_adapter(validation_type, **kwargs):
        """
        Create a certificate adapter based on validation type
        
        Args:
            validation_type (str): Type of validation ('hostname' or 'file')
            **kwargs: Additional arguments for the adapter
            
        Returns:
            CertificateAdapter: The appropriate adapter instance
        """
        if validation_type == 'hostname':
            return HostnameCertificateAdapter(
                hostname=kwargs.get('hostname'),
                port=kwargs.get('port', 443)
            )
        elif validation_type == 'file':
            return FileCertificateAdapter(
                certificate_file=kwargs.get('certificate_file')
            )
        else:
            raise ValueError(f"Unknown validation type: {validation_type}") 