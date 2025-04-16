from typing import Optional, Tuple
import sys
sys.path.append("src")
from models.certificat import Certificat
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class SignatureAlgorithmFetcher:
    """Get the signature algorithm from the certificate"""
    @staticmethod
    def get_signature_algorithm(cert: Certificat) -> Optional[Tuple]:
        """Get the signature algorithm from the certificate

            Returns:
            Tuple of (padding/ecdsa, hash_algorithm) or None if unsupported
        """
        try:
            sig_oid = cert.x509_cert.signature_algorithm_oid
            logger.info(f"[DEBUG]Signature algorithm OID: {sig_oid}")

            # Map OID to algorithm
            if sig_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                logger.info("[DEBUG]Using ECDSA with SHA256")
                return ec.ECDSA(hashes.SHA256()), hashes.SHA256()
            elif sig_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384:
                logger.info("[DEBUG]Using ECDSA with SHA384")
                return ec.ECDSA(hashes.SHA384()), hashes.SHA384()
            elif sig_oid == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512:
                logger.info("[DEBUG]Using ECDSA with SHA512")
                return ec.ECDSA(hashes.SHA512()), hashes.SHA512()
            elif sig_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
                logger.info("[DEBUG]Using RSA with SHA256")
                return padding.PKCS1v15(), hashes.SHA256()
            elif sig_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384:
                logger.info("[DEBUG]Using RSA with SHA384")
                return padding.PKCS1v15(), hashes.SHA384()
            elif sig_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512:
                logger.info("[DEBUG]Using RSA with SHA512")
                return padding.PKCS1v15(), hashes.SHA512()
            
            logger.warning(f"Unsupported signature algorithm OID: {sig_oid}")
            return None
        except Exception as e:
            logger.error(f"Error getting signature algorithm: {str(e)}")
            return None


 