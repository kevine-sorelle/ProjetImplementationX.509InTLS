from cryptography import x509
import sys
sys.path.append("src")
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from services.IssuerCertificateFetcher import IssuerCertificateFetcher
from services.EnsureCertificateObject import EnsureCertificateObject
from strategy.SignatureAlgorithmFetcher import SignatureAlgorithmFetcher
from strategy.SignatureStrategyFactory import SignatureStrategyFactory
from config.config import TRUSTED_ISSUERS
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from decorator.decoratorValidator import DecoratorValidator
from models.ValidatorDeBase import ValidatorDeBase
from utils.logger_config import setup_logger
from models.certificat import Certificat, CertificateType
from typing import Optional, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Set up logger for this module
logger = setup_logger(__name__)

class SignatureValidator(DecoratorValidator):
    """Validator for certificate signatures using decorator pattern"""
    
    def __init__(self, validator_decoree=None, issuer_cert_fetcher=None):
        """Initialize the validator with an optional decorated validator
        
        Args:
            validator_decoree: The validator to decorate. Can be None for base validation.
        """
        # If no validator provided, use ValidatorDeBase
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        
        super().__init__(validator_decoree)

    def validate(self, cert: Union[Certificat, str, x509.Certificate]) -> tuple[bool, str]:
        """Validate the certificate's signature.
        
        Args:
            certificate: Can be a Certificat object, string (PEM format), or x509.Certificate
            issuer_cert: Optional issuer certificate
            
        Returns:
            tuple[bool, str]: (is_valid, message)
        """
        
        try:
            # Ensure certificate is a Certificat object
            cert = EnsureCertificateObject.ensure_certificate_object(cert)
            if not cert:
                return False, "Invalid certificate format or conversion failed"

            base_validator = self.validator_decoree.validate(cert)
            if not base_validator:
                return False, "Base validation failed"
            try:
                
                issuer_cert = IssuerCertificateFetcher.get_issuer_certificate(cert)
                issuer_cert = EnsureCertificateObject.ensure_certificate_object(issuer_cert)
                if not issuer_cert:
                    return False, "Issuer certificate not found"

                if isinstance(issuer_cert, Certificat):
                    issuer_name = issuer_cert.get_issuer_name()
                    issuer_subject = issuer_cert.get_subject_name()
                else:
                    # For x509.Certificate objects
                    issuer_name = issuer_cert.issuer.rfc4514_string()
                    issuer_subject = issuer_cert.subject.rfc4514_string()
                if not issuer_name or not issuer_subject:
                    return False, "Certificate has no issuer information"
                
                # Verify issuer subject relationship
                if not self._verify_issuer_subject_relationship(cert, issuer_cert):
                    return False, "Issuer certificate subject does not match certificate subject"
                logger.debug(f"Issuer certificate name: {issuer_name}")
                logger.debug(f"Issuer certificate subject: {issuer_subject}")
            except Exception as e:
                logger.error(f"Error fetching issuer certificate: {str(e)}")
                return False, "Issuer certificate not found"
            
            strategy = SignatureStrategyFactory.get_signature_strategy(cert, issuer_cert=issuer_cert)
            if not strategy:
                return False, "Signature strategy not found"
            
            return strategy.validate_signature(cert, issuer_cert)
        except InvalidSignature:
            logger.error(f"Invalid signature for certificate: {cert.subject}")
            return False, "Invalid signature"
        except Exception as e:
            logger.error(f"Error validating signature: {str(e)}")
            return False, f"Error validating signature: {str(e)}"

    def _verify_issuer_subject_relationship(self, cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
        """Verify that the certificate's issuer matches the issuer certificate's subject"""
        try:
            cert_issuer = cert.issuer.rfc4514_string()
            issuer_subject = issuer_cert.subject.rfc4514_string()
            if cert_issuer != issuer_subject:
                return False
            return True
        except Exception as e:
            logger.error(f"Error verifying issuer subject relationship: {str(e)}")
            return False, f"Error verifying issuer subject relationship: {str(e)}"