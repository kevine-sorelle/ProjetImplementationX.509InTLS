"""Validator for certificate extensions"""
from cryptography import x509
from cryptography.x509 import ExtensionNotFound
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append("src")
from decorator.decoratorValidator import DecoratorValidator
from models.ValidatorDeBase import ValidatorDeBase
from utils.logger_config import setup_logger
from models.certificat import Certificat
from typing import Union, Optional, Tuple

# Set up logger for this module
logger = setup_logger(__name__)

class ExtensionValidator(DecoratorValidator):
    """Validator for certificate extensions"""

    def __init__(self, validator_decoree=None):
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        super().__init__(validator_decoree)

    def validate(self, certificate: Union[Certificat, str, x509.Certificate]) -> Tuple[bool, str]:
        """Validate the certificate's extensions.
        
        Args:
            certificate: Can be a Certificat object, string (PEM format), or x509.Certificate
            
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        try:
            # Convert input to Certificat object if needed
            cert = self._ensure_certificate_object(certificate)
            if not cert:
                return False, "Invalid certificate format or conversion failed"

            logger.debug(f"Starting extension validation for certificate: {cert.subject}")

            # First let the base validator process the certificate
            base_valid, base_msg = self.validator_decoree.validate(cert.x509_cert)
            if not base_valid:
                logger.error(f"Base validation failed: {base_msg}")
                return False, f"Base validation failed: {base_msg}"

            # Check basic constraints
            logger.debug("Checking basic constraints")
            if not self._check_basic_constraints(cert.x509_cert):
                error_msg = "Invalid basic constraints"
                logger.warning(error_msg)
                cert.add_validation_result('extensions', False, error_msg)
                return False, error_msg

            # Check key usage
            logger.debug("Checking key usage")
            if not self._check_key_usage(cert.x509_cert):
                error_msg = "Invalid key usage"
                logger.warning(error_msg)
                cert.add_validation_result('extensions', False, error_msg)
                return False, error_msg

            # Check extended key usage
            logger.debug("Checking extended key usage")
            if not self._check_extended_key_usage(cert.x509_cert):
                error_msg = "Invalid extended key usage"
                logger.warning(error_msg)
                cert.add_validation_result('extensions', False, error_msg)
                return False, error_msg

            success_msg = "All extensions are valid"
            logger.info(success_msg)
            cert.add_validation_result('extensions', True, success_msg)
            return True, success_msg

        except Exception as e:
            error_msg = f"Error during extension validation: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _ensure_certificate_object(self, certificate: Union[Certificat, str, x509.Certificate]) -> Optional[Certificat]:
        """Convert input to Certificat object if needed"""
        try:
            if isinstance(certificate, Certificat):
                return certificate
            elif isinstance(certificate, str):
                # Convert PEM string to x509.Certificate
                x509_cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
                return Certificat(x509_cert)
            elif isinstance(certificate, x509.Certificate):
                return Certificat(certificate)
            else:
                logger.error(f"Unsupported certificate type: {type(certificate)}")
                return None
        except Exception as e:
            logger.error(f"Error converting certificate: {str(e)}")
            return None

    def _check_basic_constraints(self, cert: x509.Certificate) -> bool:
        """Check basic constraints extension"""
        try:
            bc = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            logger.debug(f"Basic constraints: {bc.value}")
            # If it's a CA cert, make sure it has proper constraints
            if bc.value.ca:
                logger.debug("Certificate is a CA certificate")
                has_path_length = bc.value.path_length is not None
                if not has_path_length:
                    logger.warning("CA certificate missing path length constraint")
                return has_path_length
            logger.debug("Certificate is not a CA certificate")
            return True
        except ExtensionNotFound:
            logger.warning("No basic constraints extension found")
            return True

    def _check_key_usage(self, cert: x509.Certificate) -> bool:
        """Check key usage extension"""
        try:
            ku = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )
            logger.debug(f"Key usage: {ku.value}")
            # Log all key usage flags
            logger.debug(f"Key Usage flags: digital_signature={ku.value.digital_signature}, "
                        f"key_encipherment={ku.value.key_encipherment}, "
                        f"key_agreement={ku.value.key_agreement}")
            
            # Check if critical key usage flags are set appropriately
            is_valid = (
                ku.value.digital_signature or
                ku.value.key_encipherment or
                ku.value.key_agreement
            )
            if not is_valid:
                logger.warning("No valid key usage flags set")
            return is_valid
        except ExtensionNotFound:
            logger.warning("No key usage extension found")
            return True

    def _check_extended_key_usage(self, cert: x509.Certificate) -> bool:
        """Check extended key usage extension"""
        try:
            eku = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            )
            logger.debug(f"Extended key usage: {eku.value}")
            # Check for common extended key usages
            valid_oids = [
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
            ]
            
            # Log all extended key usages
            logger.debug(f"Extended Key Usage OIDs: {[str(oid) for oid in eku.value]}")
            
            is_valid = any(oid in valid_oids for oid in eku.value)
            if not is_valid:
                logger.warning("No valid extended key usage OIDs found")
            return is_valid
        except ExtensionNotFound:
            logger.warning("No extended key usage extension found")
            return True
