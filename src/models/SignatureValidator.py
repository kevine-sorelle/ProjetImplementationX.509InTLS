from cryptography import x509
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
sys.path.append("src")
from config import TRUSTED_ISSUERS
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from models.decoratorValidador import DecoratorValidador
from models.ValidatorDeBase import ValidatorDeBase
from utils.logger_config import setup_logger
from models.certificat import Certificat, CertificateType
from typing import Optional, Union

# Set up logger for this module
logger = setup_logger(__name__)

class SignatureValidator(DecoratorValidador):
    """Validator for certificate signatures using decorator pattern"""
    
    def __init__(self, validator_decoree=None):
        """Initialize the validator with an optional decorated validator
        
        Args:
            validator_decoree: The validator to decorate. Can be None for base validation.
        """
        # If no validator provided, use ValidatorDeBase
        if validator_decoree is None:
            validator_decoree = ValidatorDeBase()
        super().__init__(validator_decoree)

    def validate(self, certificate: Union[Certificat, str, x509.Certificate], issuer_cert: Optional[Certificat] = None) -> tuple[bool, str]:
        """Validate the certificate's signature.
        
        Args:
            certificate: Can be a Certificat object, string (PEM format), or x509.Certificate
            issuer_cert: Optional issuer certificate
            
        Returns:
            tuple[bool, str]: (is_valid, message)
        """
        try:
            # Convert input to Certificat object if needed
            cert = self._ensure_certificate_object(certificate)
            if not cert:
                return False, "Invalid certificate format or conversion failed"

            logger.debug(f"Starting signature validation for certificate: {cert.subject}")
            
            # Log certificate details
            logger.debug(f"Certificate type: {cert.certificate_type.value}")
            logger.debug(f"Signature algorithm: {cert.x509_cert.signature_algorithm_oid}")
            logger.debug(f"Public key type: {type(cert.get_public_key()).__name__}")
            
            # If no issuer certificate provided, try to fetch it
            if not issuer_cert and cert.certificate_type == CertificateType.TRADITIONAL:
                logger.debug("No issuer certificate provided, attempting to fetch from AIA")
                issuer_cert = self._get_issuer_certificate(cert)
                if not issuer_cert:
                    return False, "Could not fetch issuer certificate from AIA extension"

            # First let the base validator process the certificate
            base_valid = self.validator_decoree.validate(cert.x509_cert)
            if not base_valid:
                return False, "Base validation failed"

            # Validate based on certificate type
            if cert.certificate_type == CertificateType.TRADITIONAL:
                valid = self._validate_traditional(cert, issuer_cert)
                return valid, "Traditional signature validation successful" if valid else "Traditional signature validation failed"
            elif cert.certificate_type == CertificateType.PQC:
                valid = self._validate_pqc(cert, issuer_cert)
                return valid, "PQC signature validation successful" if valid else "PQC signature validation failed"
            else:  # HYBRID
                valid = self._validate_hybrid(cert, issuer_cert)
                return valid, "Hybrid signature validation successful" if valid else "Hybrid signature validation failed"

        except Exception as e:
            error_msg = f"Error during signature validation: {str(e)}"
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

    def _validate_traditional(self, cert: Certificat, issuer_cert: Optional[Certificat]) -> bool:
        """Validate traditional RSA/ECC signature"""
        try:
            # For ECDSA certificates, we need the issuer's public key
            if not issuer_cert:
                error_msg = "Issuer certificate required for signature validation"
                logger.error(error_msg)
                cert.add_validation_result('signature_traditional', False, error_msg)
                return False

            public_key = issuer_cert.get_public_key()
            
            # Log certificate details for debugging
            sig_algorithm = cert.x509_cert.signature_algorithm_oid
            logger.debug(f"Certificate signature algorithm: {sig_algorithm}")
            logger.debug(f"Public key type: {type(public_key).__name__}")
            
            # Log key details
            if isinstance(public_key, rsa.RSAPublicKey):
                logger.debug(f"RSA key size: {public_key.key_size} bits")
            elif isinstance(public_key, EllipticCurvePublicKey):
                logger.debug(f"EC curve: {public_key.curve.name}")
            
            # Use appropriate padding based on key type
            if isinstance(public_key, rsa.RSAPublicKey):
                logger.debug("Using RSA signature verification with PKCS1v15 padding")
                public_key.verify(
                    cert.x509_cert.signature,
                    cert.x509_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.x509_cert.signature_hash_algorithm,
                )
            elif isinstance(public_key, EllipticCurvePublicKey):
                logger.debug("Using ECDSA signature verification")
                public_key.verify(
                    cert.x509_cert.signature,
                    cert.x509_cert.tbs_certificate_bytes,
                    ECDSA(cert.x509_cert.signature_hash_algorithm)
                )
            else:
                error_msg = f"Unsupported key type: {type(public_key).__name__}"
                logger.error(error_msg)
                cert.add_validation_result('signature_traditional', False, error_msg)
                return False
            
            success_msg = "Traditional signature validation successful"
            logger.info(success_msg)
            cert.add_validation_result('signature_traditional', True, success_msg)
            return True

        except InvalidSignature as e:
            error_msg = f"Invalid traditional signature: {str(e)}"
            logger.warning(error_msg)
            cert.add_validation_result('signature_traditional', False, error_msg)
            return False
        except Exception as e:
            error_msg = f"Error during traditional signature validation: {str(e)}"
            logger.error(error_msg)
            cert.add_validation_result('signature_traditional', False, error_msg)
            return False

    def _validate_pqc(self, cert: Certificat, issuer_cert: Optional[Certificat]) -> bool:
        """Validate post-quantum signature"""
        try:
            pqc_info = cert.get_pqc_algorithm_info()
            if not pqc_info:
                error_msg = "No PQC algorithm information found"
                logger.error(error_msg)
                cert.add_validation_result('signature_pqc', False, error_msg)
                return False

            # Here you would implement specific validation for each PQC algorithm
            # This is a placeholder for actual PQC validation logic
            for algo_name, info in pqc_info.items():
                logger.debug(f"Validating {algo_name} signature")
                # Add specific validation logic for each PQC algorithm
                
            success_msg = "PQC signature validation successful"
            logger.info(success_msg)
            cert.add_validation_result('signature_pqc', True, success_msg)
            return True

        except Exception as e:
            error_msg = f"PQC signature validation failed: {str(e)}"
            logger.error(error_msg)
            cert.add_validation_result('signature_pqc', False, error_msg)
            return False

    def _validate_hybrid(self, cert: Certificat, issuer_cert: Optional[Certificat]) -> bool:
        """Validate both traditional and PQC signatures for hybrid certificates"""
        traditional_valid = self._validate_traditional(cert, issuer_cert)
        pqc_valid = self._validate_pqc(cert, issuer_cert)
        
        is_valid = traditional_valid and pqc_valid
        message = "Hybrid signature validation " + ("successful" if is_valid else "failed")
        cert.add_validation_result('signature_hybrid', is_valid, message)
        
        return is_valid

    def _validate_signature(self, certificate: x509.Certificate):
        """Validate the signature of the certificate"""
        if isinstance(certificate, str):
            certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

        try:
            # For self-signed certificates
            if certificate.issuer == certificate.subject:
                logger.debug("Self-signed certificate detected")
                return self.verify_certificate_signature(certificate)

            # For CA-signed certificates
            return self.verify_certificate_signature(certificate)
        except Exception as e:
            logger.error(f"Error in signature validation: {str(e)}")
            return False

    def get_public_key(self, certificate: x509.Certificate):
        """Extract the public key from the certificate"""
        return certificate.public_key()

    def get_signature(self, certificate: x509.Certificate):
        """Extract the signature from the certificate"""
        return certificate.signature

    def verify_certificate_signature(self, cert: x509.Certificate, issuer_cert=None):
        """Verify the signature of the certificate"""
        try:
            # Use issuer's public key if available, otherwise use cert's own key (self-signed)
            public_key = issuer_cert.public_key() if issuer_cert else self.get_public_key(cert)
            signature = self.get_signature(cert)
            
            # Log key type for debugging
            logger.debug(f"Public key type: {type(public_key).__name__}")
            
            # Verify based on key type
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True
            elif isinstance(public_key, EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    cert.tbs_certificate_bytes,
                    ECDSA(cert.signature_hash_algorithm)
                )
                return True
            else:
                raise ValueError(f"Unsupported key type: {type(public_key).__name__}")
        except InvalidSignature:
            logger.error("Invalid signature detected")
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            raise ValueError(f"Signature verification error: {str(e)}")

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

    def _get_issuer_certificate(self, cert: Certificat) -> Optional[Certificat]:
        """Fetch the issuer certificate from the certificate's AIA extension"""
        try:
            # Get the AIA extension
            aia = cert.x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            
            # Look for the CA Issuers URI
            for access_description in aia.value:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_url = access_description.access_location.value
                    logger.debug(f"Found issuer certificate URL: {issuer_url}")
                    
                    # Download the issuer certificate
                    import requests
                    response = requests.get(issuer_url)
                    if response.status_code == 200:
                        try:
                            # Try to load as PEM first
                            issuer_cert = x509.load_pem_x509_certificate(response.content, default_backend())
                        except ValueError:
                            # If PEM fails, try DER
                            issuer_cert = x509.load_der_x509_certificate(response.content, default_backend())
                        
                        logger.debug(f"Successfully loaded issuer certificate for: {issuer_cert.subject}")
                        return Certificat(issuer_cert)
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

