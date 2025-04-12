from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
import os
import sys
sys.path.append("src")
from models.KEM import KEM
from models.keyGenerator import KeyGenerator

class CertificateGenerator:
    """Class for generating X.509 certificates with optional KEM integration"""
    
    def __init__(self):
        self.key_generator = KeyGenerator()
        self.kem = KEM()
    
    def generate_certificate(self, subject, organization, country, validity_days=365, key_size=256, include_kem=False):
        """
        Generate a new X.509 certificate with optional KEM integration
        
        Args:
            subject (str): Common Name (CN) for the certificate
            organization (str): Organization name
            country (str): Two-letter country code
            validity_days (int): Number of days the certificate is valid
            key_size (int): Size of the EC key in bits
            include_kem (bool): Whether to include KEM keys in the certificate
            
        Returns:
            str: The certificate in PEM format
        """
        # Generate EC key pair
        private_key = self.key_generator.generateECKey(key_size)
        
        # Generate KEM keys if requested
        kem_public_key = None
        kem_private_key = None
        shared_secret = None
        if include_kem:
            kem_public_key, shared_secret = self.kem.encapsulate()
            kem_private_key = self.kem.decapsulate(kem_public_key)
        
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
            # Create a custom extension for KEM public key
            # This is a simplified example - in a real implementation, you would use
            # a proper OID and format for the KEM public key
            kem_oid = x509.ObjectIdentifier("1.3.6.1.4.1.54321.1.1")  # Example OID
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
        
        # Also get the private key in PEM format
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode('utf-8')
        
        # Return both certificate and private key
        return {
            'certificate': cert_pem,
            'private_key': private_key_pem,
            'kem_public_key': kem_public_key.hex() if kem_public_key else None,
            'kem_private_key': kem_private_key.hex() if kem_private_key else None
        } 