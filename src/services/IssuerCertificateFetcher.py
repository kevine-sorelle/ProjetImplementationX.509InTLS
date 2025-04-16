from typing import Optional, Union
import os
import hashlib
import sys
sys.path.append("src")
from models.certificat import Certificat
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

CACHE_DIR = "cache/issuer_certs"
os.makedirs(CACHE_DIR, exist_ok=True)
class IssuerCertificateFetcher:
    """Fetch the issuer certificate from the certificate's AIA extension"""
    @staticmethod
    def get_issuer_certificate(cert: Union[Certificat, x509.Certificate, str]) -> Optional[x509.Certificate]:
        """Fetch the issuer certificate from the certificate's AIA extension"""
        try:
            # Get the AIA extension
            aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if not aia:
                logger.warning("No AIA extension found in certificate")
                return None
            
            # Look for the CA Issuers URI
            for access_description in aia.value:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_url = access_description.access_location.value
                    logger.debug(f"Found issuer certificate URL: {issuer_url}")

                    # Check local cache
                    cert_hash = _hash_url(issuer_url)
                    cert_path = os.path.join(CACHE_DIR, f"{cert_hash}.pem")
                    if os.path.exists(cert_path):
                        logger.debug(f"Loading issuer certificate from cache: {cert_path}")
                        with open(cert_path, "rb") as f:
                            cached_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                            return cached_cert
                    
                    # Download the issuer certificate
                    import requests
                    response = requests.get(issuer_url, timeout=10)
                    if response.status_code == 200:
                        try:
                            # Try to load as DER first
                            issuer_cert = x509.load_der_x509_certificate(response.content, default_backend())
                        except ValueError:
                            # If DER fails, try PEM
                            issuer_cert = x509.load_pem_x509_certificate(response.content, default_backend())
                        
                        logger.debug(f"Successfully loaded issuer certificate for: {issuer_cert.subject}")
                        logger.debug(f"Loaded issuer cert from: {issuer_url}")
                        return issuer_cert
                    else:
                        logger.error(f"Failed to download issuer certificate from {issuer_url}")
                        return None
            
            logger.warning("No CA Issuers URI found in AIA extension")
            return None
            
        except x509.extensions.ExtensionNotFound:
            logger.warning("No AIA extension found in certificate")
            return None
        except Exception as e:
            logger.error(f"Error fetching issuer certificate: {str(e)}")
            return None

def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()
