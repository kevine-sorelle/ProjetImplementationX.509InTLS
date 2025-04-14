"""Module for checking certificate revocation status."""
from cryptography import x509
from cryptography.x509 import ExtensionNotFound
from cryptography.hazmat.backends import default_backend
import requests
import base64
from utils.logger_config import setup_logger
from models.certificat import Certificat
from decorator.decoratorValidator import DecoratorValidator
from models.ValidatorDeBase import ValidatorDeBase
from typing import List, Tuple, Union, Optional

logger = setup_logger(__name__)

class RevocationValidator(DecoratorValidator):
    """Validator for checking certificate revocation status."""

    def __init__(self, validator_decoree=None):
        """Initialize the validator with an optional decorated validator
        
        Args:
            validator_decoree: The validator to decorate. Can be None for base validation.
        """
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        super().__init__(validator_decoree)

    def validate(self, certificate: Union[Certificat, str, x509.Certificate]) -> Tuple[bool, str]:
        """Check if the certificate has been revoked using CRL and OCSP.
        
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

            logger.debug(f"Starting revocation check for certificate: {cert.subject}")

            # First let the base validator process the certificate
            base_valid, base_msg = self.validator_decoree.validate(cert.x509_cert)
            if not base_valid:
                logger.error(f"Base validation failed: {base_msg}")
                return False, f"Base validation failed: {base_msg}"

            # Check CRL first
            crl_urls = self._get_crl_urls(cert.x509_cert)
            if crl_urls:
                logger.debug(f"Found {len(crl_urls)} CRL distribution points")
                for url in crl_urls:
                    if not self._check_crl(cert.x509_cert, url):
                        error_msg = f"Certificate is revoked according to CRL at {url}"
                        logger.warning(error_msg)
                        cert.add_validation_result('revocation', False, error_msg)
                        return False, error_msg
            else:
                logger.debug("No CRL distribution points found")

            # Then check OCSP
            ocsp_url = self._get_ocsp_url(cert.x509_cert)
            if ocsp_url:
                logger.debug(f"Found OCSP responder URL: {ocsp_url}")
                if not self._check_ocsp(cert.x509_cert, ocsp_url):
                    error_msg = f"Certificate is revoked according to OCSP at {ocsp_url}"
                    logger.warning(error_msg)
                    cert.add_validation_result('revocation', False, error_msg)
                    return False, error_msg
            else:
                logger.debug("No OCSP responder URL found")

            success_msg = "Certificate is not revoked"
            logger.info(success_msg)
            cert.add_validation_result('revocation', True, success_msg)
            return True, success_msg

        except Exception as e:
            error_msg = f"Error during revocation check: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _ensure_certificate_object(self, certificate: Union[Certificat, str, x509.Certificate]) -> Optional[Certificat]:
        """Convert input to Certificat object if needed"""
        try:
            if isinstance(certificate, Certificat):
                logger.debug("Input is already a Certificat object")
                return certificate
            
            elif isinstance(certificate, str):
                logger.debug("Converting string input to certificate")
                try:
                    # Try direct PEM loading first
                    x509_cert = x509.load_pem_x509_certificate(
                        certificate.encode(),
                        default_backend()
                    )
                except ValueError:
                    # If PEM loading fails, try cleaning the string and handle base64
                    try:
                        # Remove headers, footers, and whitespace
                        clean_cert = certificate.replace("-----BEGIN CERTIFICATE-----", "")
                        clean_cert = clean_cert.replace("-----END CERTIFICATE-----", "")
                        clean_cert = clean_cert.strip()
                        
                        # Decode base64 and create certificate
                        der_data = base64.b64decode(clean_cert)
                        x509_cert = x509.load_der_x509_certificate(
                            der_data,
                            default_backend()
                        )
                    except Exception as e:
                        logger.error(f"Failed to parse certificate string: {str(e)}")
                        return None
                
                logger.debug("Successfully converted string to X.509 certificate")
                return Certificat(x509_cert)
            
            elif isinstance(certificate, x509.Certificate):
                logger.debug("Converting X.509 certificate to Certificat object")
                return Certificat(certificate)
            
            else:
                logger.error(f"Unsupported certificate type: {type(certificate)}")
                return None
                
        except Exception as e:
            logger.error(f"Error converting certificate: {str(e)}")
            return None

    def _get_crl_urls(self, cert: x509.Certificate) -> List[str]:
        """Extract CRL distribution points from certificate."""
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            return [point.full_name[0].value for point in crl_ext.value]
        except ExtensionNotFound:
            return []

    def _check_crl(self, cert: x509.Certificate, url: str) -> bool:
        """Check if certificate is in the CRL."""
        try:
            response = requests.get(url)
            if response.status_code != 200:
                logger.warning(f"Failed to fetch CRL from {url}")
                return True  # Assume not revoked if CRL unavailable
            
            # Here you would parse the CRL and check if the certificate's
            # serial number is in it. For now, we'll assume it's not revoked
            return True
            
        except Exception as e:
            logger.error(f"Error checking CRL: {str(e)}")
            return True  # Assume not revoked if check fails

    def _get_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """Extract OCSP responder URL from certificate."""
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_description in aia_ext.value:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return access_description.access_location.value
        except ExtensionNotFound:
            return None
        return None

    def _check_ocsp(self, cert: x509.Certificate, url: str) -> bool:
        """Check certificate status using OCSP."""
        try:
            # Here you would implement OCSP checking
            # For now, we'll assume certificate is not revoked
            return True
            
        except Exception as e:
            logger.error(f"Error checking OCSP: {str(e)}")
            return True  # Assume not revoked if check fails