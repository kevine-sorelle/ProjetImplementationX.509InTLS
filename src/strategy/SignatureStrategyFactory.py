import sys
sys.path.append("src")
from models.certificat import Certificat
from services.EnsureCertificateObject import EnsureCertificateObject
from strategy.ECDSASignatureStrategy import ECDSASignatureStrategy
from strategy.RSASignatureStrategy import RSASignatureStrategy
from strategy.SignatureStrategy import SignatureStrategy
from cryptography import x509
from cryptography.x509.oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import Union
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
logger = logging.getLogger(__name__)

class SignatureStrategyFactory:
    @staticmethod
    def get_signature_strategy(cert: Union[Certificat, str, x509.Certificate], issuer_cert: Union[Certificat, str, x509.Certificate] = None) -> SignatureStrategy:
        #cert = EnsureCertificateObject.ensure_certificate_object(cert)
        #issuer_cert = EnsureCertificateObject.ensure_certificate_object(issuer_cert)
        # Handle certificate input
        if isinstance(cert, str):
                cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        elif isinstance(cert, Certificat):
            cert = cert.x509_cert
        
        # Handle issuer certificate input
        if isinstance(issuer_cert, str):
                issuer_cert = x509.load_pem_x509_certificate(issuer_cert.encode(), default_backend())
        elif isinstance(issuer_cert, Certificat):
            issuer_cert = issuer_cert.x509_cert
        if not issuer_cert or not cert:
                raise ValueError("Invalid certificate format or conversion failed")
        
        oid = cert.signature_algorithm_oid
        logger.info(f"[DEBUG]Signature algorithm OID: {oid}")
        logger.info(f"[DEBUG]Issuer public key type: {type(issuer_cert).__name__}")

        try:
                issuer_key = issuer_cert.public_key()
        except AttributeError:
            try:
                issuer_key = issuer_cert.get_public_key()
            except Exception as e:
                return False, f"Failed to get issuer public key: {str(e)}"
        
        if isinstance(issuer_key, rsa.RSAPublicKey):
            logger.info("[DEBUG]Using RSA signature strategy (issuer key is RSA)")
            return RSASignatureStrategy()
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            logger.info("[DEBUG]Using ECDSA signature strategy (issuer key is EC)")
            return ECDSASignatureStrategy()
        else:
            raise ValueError(f"Unsupported issuer key type: {type(issuer_key).__name__}")
            
