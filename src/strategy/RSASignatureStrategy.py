from typing import Optional, Union
import sys
sys.path.append("src")
from models.certificat import Certificat
from services.EnsureCertificateObject import EnsureCertificateObject
from strategy.SignatureStrategy import SignatureStrategy
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
import logging
logger = logging.getLogger(__name__)

class RSASignatureStrategy(SignatureStrategy):
    def validate_signature(self, cert: Union[Certificat, str, x509.Certificate], issuer_cert: Optional[Certificat] = None) -> tuple:
        try:
            # Handle different types of cert and issuer_certinput
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
            if not isinstance(issuer_key, rsa.RSAPublicKey):
                raise ValueError("Issuer key is not an RSA key")
            
            if cert.issuer.rfc4514_string() != issuer_cert.subject.rfc4514_string():
                return False, "Certificate issuer does not match issuer certificate subject"
            
            if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
                signature_hash_algorithm = hashes.SHA256()
            elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384:
                signature_hash_algorithm = hashes.SHA384()
            elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512:
                signature_hash_algorithm = hashes.SHA512()
            else:
                return False, f"Unsupported signature algorithm: {cert.signature_algorithm_oid}"
            
            # Verify the signature
            try:
                issuer_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    signature_hash_algorithm
                )
            except Exception as e:
                logger.info(f"[DEBUG] Signature verification failed: {str(e)}")
                return False, f"Signature verification failed: {str(e)}"
            return True, "Signature is valid"
        except Exception as e:
            return False, f"Signature validation failed: {str(e)}"
