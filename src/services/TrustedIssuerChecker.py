from cryptography import x509
from cryptography.x509.oid import NameOID
from src.models.certificat import Certificat
import logging

logger = logging.getLogger(__name__)

class TrustedIssuerChecker:
    def validate_trusted_issuer(self, certificate: x509.Certificate, trusted_issuers: list):
        """Validate the issuer against a trusted issuers list."""
        if not trusted_issuers:
            logger.warning("No trusted issuers configured, accepting all")
            return True
            
        # Get the full issuer name
        issuer_dn = certificate.issuer
        actual_issuer = issuer_dn.rfc4514_string()
        
        # Log the actual issuer name for debugging
        logger.debug(f"Checking issuer: {actual_issuer}")
        
        # Check organization name specifically
        org_name = None
        for attr in issuer_dn:
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                org_name = attr.value
                break
        
        if org_name:
            logger.debug(f"Found organization name: {org_name}")
            # Check if org_name matches any trusted issuer
            for trusted_issuer in trusted_issuers:
                if trusted_issuer.lower() in org_name.lower():
                    logger.debug(f"Matched trusted issuer: {trusted_issuer}")
                    return True
        
        logger.warning(f"No matching trusted issuer found for: {actual_issuer}")
        return False
