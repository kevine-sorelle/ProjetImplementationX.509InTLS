from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import List
import re
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class CertificateParser:

    @staticmethod
    def parse_pem_chain(pem_chain_str: str) -> List[x509.Certificate]:
        """Parses a PEM-encoded certificate chain string into a list of certificates.

        Args:
            pem_chain_str: A string containing one or more PEM-encoded certificates.

        Returns:
            A list of cryptography.x509.Certificate objects.
            Returns an empty list if the input is invalid or empty.
        """
        if not pem_chain_str or not isinstance(pem_chain_str, str):
            logger.warning("Invalid or empty PEM chain string provided for parsing.")
            return []

        # Regex to find PEM certificate blocks
        pem_cert_regex = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL)
        
        certificates = []
        matches = pem_cert_regex.findall(pem_chain_str)
        
        if not matches:
            logger.warning("No PEM certificate blocks found in the provided string.")
            return []
            
        for cert_content in matches:
            full_pem = f"-----BEGIN CERTIFICATE-----{cert_content.strip()}\n-----END CERTIFICATE-----".encode('utf-8')
            try:
                cert = x509.load_pem_x509_certificate(full_pem, default_backend())
                certificates.append(cert)
            except ValueError as e:
                logger.error(f"Failed to parse a certificate block from the chain: {e}")
                # Optionally continue to parse other certificates or raise an error
        
        logger.debug(f"Parsed {len(certificates)} certificates from the PEM chain.")
        return certificates 