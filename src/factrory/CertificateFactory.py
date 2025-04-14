from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
import sys
sys.path.append("src")
from models.KEM import KEM
from strategy.ECKeyStrategy import ECKeyStrategy
from strategy.RSAKeyStrategy import RSAKeyStrategy
from strategy.KeyGenerationStrategy import KeyGenerationStrategy


class CertificateFactory:
    """Factory class for creating certificates with different configurations"""
    
    @staticmethod
    def create_certificate(
        subject: str,
        organization: str,
        country: str,
        validity_days: int = 365,
        key_type: str = "EC",
        key_size: int = 256,
        include_kem: bool = False
    ):
        """
        Create a certificate with the specified parameters
        
        Args:
            subject (str): Common Name (CN) for the certificate
            organization (str): Organization name
            country (str): Two-letter country code
            validity_days (int): Number of days the certificate is valid
            key_type (str): Type of key to generate ("RSA" or "EC")
            key_size (int): Size of the key in bits
            include_kem (bool): Whether to include KEM keys in the certificate
            
        Returns:
            dict: Dictionary containing certificate and key information
        """
        # Select key generation strategy
        strategy = {
            "RSA": RSAKeyStrategy(),
            "EC": ECKeyStrategy()
        }.get(key_type.upper(), ECKeyStrategy())
        
        # Generate key pair
        private_key = strategy.generate_key(key_size)
        
        # Generate KEM keys if requested
        kem_public_key = None
        kem_private_key = None
        if include_kem:
            kem = KEM()
            kem_public_key, shared_secret = kem.encapsulate()
            kem_private_key = kem.decapsulate(kem_public_key)
        
        # Create subject name
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ])
        
        # Create issuer name (self-signed for now)
        issuer_name = subject_name
        
        # Create certificate builder
        builder = x509.CertificateBuilder()
        
        # Set certificate properties
        builder = builder.subject_name(subject_name)
        builder = builder.issuer_name(issuer_name)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        builder = builder.public_key(private_key.public_key())
        
        # Add KEM extension if requested
        if include_kem and kem_public_key:
            kem_oid = x509.ObjectIdentifier("1.3.6.1.4.1.54321.1.1")
            builder = builder.add_extension(
                x509.UnrecognizedExtension(kem_oid, kem_public_key),
                critical=False
            )
        
        # Sign the certificate
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
        
        # Convert to PEM format
        cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode('utf-8')
        
        return {
            'certificate': cert_pem,
            'private_key': private_key_pem,
            'kem_public_key': kem_public_key.hex() if kem_public_key else None,
            'kem_private_key': kem_private_key.hex() if kem_private_key else None
        }