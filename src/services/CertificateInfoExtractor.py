import sys
sys.path.append("src")
from models.certificat import Certificat
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timezone
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

class CertificateInfoExtractor:
   @staticmethod
   def extract_certificate_info(cert):
        """
        Extract useful information from a certificate.
        
        Args:
            cert: The certificate to extract information from
            
        Returns:
            dict: Certificate information
        """
        logger.debug("[DEBUG] Running _extract_certificate_info")

        # if cert is a string, convert it to a certificate object
        logger.debug(f"[DEBUG] Cert type: {type(cert)}")
        if isinstance(cert, str):
            logger.debug("[DEBUG] Received a string cert, attempting to parse...")
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            logger.debug(f"[DEBUG] Parsed cert type: {type(cert)}")

        info = {}
        
        try:
            # Create Certificat object if needed
            if not isinstance(cert, Certificat):
                cert_obj = Certificat(x509_cert=cert)
            else:
                cert_obj = cert

            # Verify we have a valid x509_cert
            if not cert_obj.x509_cert:
                logger.error("Invalid certificate object: x509_cert is None")
                raise ValueError("Invalid certificate object: x509_cert is None")

            # Extract subject information
            subject = cert_obj.x509_cert.subject
            logger.debug(f"[DEBUG] Subject: {subject}")
            for attr in subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    info['subject_cn'] = attr.value
                elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                    info['subject_o'] = attr.value
                elif attr.oid == x509.NameOID.COUNTRY_NAME:
                    info['subject_c'] = attr.value
            
            # Extract validity period using the x509_cert attribute
            logger.debug(f"[DEBUG] Not valid before: {cert_obj.x509_cert.not_valid_before_utc}")
            logger.debug(f"[DEBUG] Not valid after: {cert_obj.x509_cert.not_valid_after_utc}")
            if cert_obj.x509_cert.not_valid_before_utc and cert_obj.x509_cert.not_valid_after_utc:
                info['not_before'] = cert_obj.x509_cert.not_valid_before_utc.strftime('%Y-%m-%d')
                info['not_after'] = cert_obj.x509_cert.not_valid_after_utc.strftime('%Y-%m-%d')
            
                # Calculate days remaining using timezone-aware current time
                now_utc = datetime.now(timezone.utc)
                logger.debug(f"[DEBUG] Now (UTC): {now_utc}")
                logger.debug(f"[DEBUG] Not valid after (UTC): {cert_obj.x509_cert.not_valid_after_utc}")
                days_remaining = (cert_obj.x509_cert.not_valid_after_utc - now_utc).days
                info['days_remaining'] = max(0, days_remaining)
                logger.debug(f"[DEBUG] Days remaining calculated: {info['days_remaining']}")
            else:
                logger.warning("Invalid certificate validity period: not_valid_before or not_valid_after is None")
                info['not_before'] = 'Unknown'
                info['not_after'] = 'Unknown'
                info['days_remaining'] = 0
            
            # Extract key information
            public_key = cert_obj.get_public_key()
            logger.debug(f"[DEBUG] Public key: {public_key}")
            if isinstance(public_key, rsa.RSAPublicKey):
                info['key_type'] = 'RSA'
                info['key_size'] = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                info['key_type'] = 'ECDSA'
                info['key_size'] = public_key.curve.key_size
            else:
                info['key_type'] = 'Unknown'
                info['key_size'] = 0
            
            # Extract signature algorithm
            try:
                sig_algorithm = cert_obj.get_signature_algorithm()
                if hasattr(sig_algorithm, 'name'):
                    info['signature_algorithm'] = sig_algorithm.name
                else:
                    info['signature_algorithm'] = str(sig_algorithm)
            except AttributeError:
                info['signature_algorithm'] = 'Unknown'
            
        except Exception as e:
            logger.error(f"Error extracting certificate info: {str(e)}", exc_info=True)
            # Set default values if extraction fails
            info.setdefault('subject_cn', 'Unknown')
            info.setdefault('subject_o', 'Unknown')
            info.setdefault('subject_c', 'Unknown')
            info.setdefault('not_before', 'Unknown')
            info.setdefault('not_after', 'Unknown')
            info.setdefault('days_remaining', 0)
            info.setdefault('key_type', 'Unknown')
            info.setdefault('key_size', 0)
            info.setdefault('signature_algorithm', 'Unknown')
            
        return info


