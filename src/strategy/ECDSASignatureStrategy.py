from typing import Optional, Union
from cryptography import x509
import sys

from src.services.EnsureCertificateObject import EnsureCertificateObject
sys.path.append("src")
from models.certificat import Certificat
from strategy.SignatureStrategy import SignatureStrategy
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import logging
logger = logging.getLogger(__name__)
class ECDSASignatureStrategy(SignatureStrategy):
    
    def validate_signature(self, cert: Union[Certificat, str, x509.Certificate], issuer_cert: Optional[Union[Certificat, str, x509.Certificate]] = None) -> tuple[bool, str]:
        try:
            # Handle different types of issuer_cert input
            cert = EnsureCertificateObject.ensure_certificate_object(cert)
            issuer_cert = EnsureCertificateObject.ensure_certificate_object(issuer_cert)
            
            # Get the public key from the issuer certificate
            try:
                issuer_key = issuer_cert.public_key()
                logger.info(f"[DEBUG]Issuer public key type: {type(issuer_key).__name__}")
            except AttributeError:
                try:
                    issuer_key = issuer_cert.get_public_key()
                    logger.info(f"[DEBUG]Issuer public key type: {type(issuer_key).__name__}")
                except Exception as e:
                    return False, f"Failed to get issuer public key: {str(e)}"
            
            if not isinstance(issuer_key, ec.EllipticCurvePublicKey):
                return False, "Issuer key is not an EC key"
            
            if cert.issuer.rfc4514_string() != issuer_cert.subject.rfc4514_string():
                return False, "Certificate issuer does not match issuer certificate subject"
            
            if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                signature_hash_algorithm = hashes.SHA256()
            elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384:
                signature_hash_algorithm = hashes.SHA384()
            elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512:
                signature_hash_algorithm = hashes.SHA512()
            else:
                return False, f"Unsupported signature algorithm: {cert.signature_algorithm_oid}"
            
            # Verify the signature
            try:
                logger.info(f"[DEBUG] Signature length: {len(cert.signature)}")
                logger.info(f"[DEBUG] TBS certificate bytes length: {len(cert.tbs_certificate_bytes)}")
                issuer_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(signature_hash_algorithm))
                return True, "Signature is valid"
            except Exception as e:
                logger.info(f"[DEBUG] Signature verification failed: {str(e)}")
                return False, f"Signature verification failed: {str(e)}"
            
        except Exception as e:
            logger.info(f"[DEBUG] Error during signature validation: {str(e)}")
            return False, f"Error during signature validation: {str(e)}"

