"""Classe pour stocker les informations d'un certificat."""
from cryptography import x509
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
from utils.logger_config import setup_logger
import sys
sys.path.append("src")
from config.config import PQC_OIDS


# Set up logger for this module
logger = setup_logger(__name__)

class CertificateType(Enum):
    """Enumeration of certificate types"""
    TRADITIONAL = "traditional"  # RSA/ECC certificates
    PQC = "pqc"                 # Post-quantum certificates
    HYBRID = "hybrid"           # Hybrid certificates (traditional + PQC)

class Certificat:
    _instance = None
    _x509_cert = None

    def __new__(cls, x509_cert=None):
        if cls._instance is None:
            cls._instance = super(Certificat, cls).__new__(cls)
            cls._instance._x509_cert = x509_cert
        return cls._instance
    
    def __init__(self, x509_cert=None):
        #self.x509_cert = x509_cert
        self._validation_results: Dict[str, Dict[str, Any]] = {}
        self._cert_type = self._determine_certificate_type()
        
        # Extract and store basic certificate information
        if self._x509_cert:
            self.subject = self._x509_cert.subject.rfc4514_string()
            self.issuer = self._x509_cert.issuer.rfc4514_string()
            self.not_valid_before = self._x509_cert.not_valid_before_utc
            self.not_valid_after = self._x509_cert.not_valid_after_utc
            self.serial_number = self._x509_cert.serial_number
            
            logger.debug(f"Created certificate wrapper for {self.subject} of type {self._cert_type.value}")

    @property
    def x509_cert(self) -> x509.Certificate:
        """Get the underlying X.509 certificate"""
        return self._x509_cert
    
    @x509_cert.setter
    def x509_cert(self, value):
        """Set the underlying X.509 certificate if it's not already set"""
        if self._x509_cert is None:
            self._x509_cert = value
            # Re-initialize the certificate wrapper with the new certificate
            if value:
                #self.__init__(value)
                self.subject = value.subject.rfc4514_string()
                self.issuer = value.issuer.rfc4514_string()
                self.not_valid_before = value.not_valid_before_utc
                self.not_valid_after = value.not_valid_after_utc
                self.serial_number = value.serial_number
                self._cert_type = self._determine_certificate_type()
        else:
            logger.warning("Certificate is already set and cannot be changed (Singleton pattern)")

    @classmethod
    def reset(cls):
        """Reset the singleton instance (useful for testing)"""
        cls._instance = None
        cls._x509_cert = None

    def _determine_certificate_type(self) -> CertificateType:
        """Determine if this is a traditional, PQC, or hybrid certificate"""
        sig_oid = self.x509_cert.signature_algorithm_oid if self.x509_cert else None
        
        # Check if certificate uses PQC algorithms
        has_pqc = any(pqc_oid in self.get_all_oids() for pqc_oid in PQC_OIDS.values()) if self.x509_cert else False
        
        # Check if certificate uses traditional algorithms
        has_traditional = not has_pqc or self._has_traditional_algorithms() if self.x509_cert else False
        
        if has_pqc and has_traditional:
            return CertificateType.HYBRID
        elif has_pqc:
            return CertificateType.PQC
        else:
            return CertificateType.TRADITIONAL

    def _has_traditional_algorithms(self) -> bool:
        """Check if certificate uses traditional cryptographic algorithms"""
        sig_oid = self.x509_cert.signature_algorithm_oid if self.x509_cert else None
        # List of common traditional algorithm OIDs (RSA, ECDSA, etc.)
        traditional_oids = [
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256,
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256,
            # Add other traditional algorithm OIDs as needed
        ]
        return sig_oid in traditional_oids if self.x509_cert else False

    def get_all_oids(self) -> List[x509.ObjectIdentifier]:
        """Get all OIDs used in the certificate"""
        oids = [self.x509_cert.signature_algorithm_oid] if self.x509_cert else []
        oids.extend(self.get_extension_oids())
        return oids

    @property
    def certificate_type(self) -> CertificateType:
        """Get the type of certificate (traditional, PQC, or hybrid)"""
        return self._cert_type

    def requires_pqc_validation(self) -> bool:
        """Check if certificate requires PQC-specific validation"""
        return self._cert_type in [CertificateType.PQC, CertificateType.HYBRID]

    def get_pqc_algorithm_info(self) -> Optional[Dict[str, Any]]:
        """Get information about PQC algorithms used in the certificate"""
        if not self.requires_pqc_validation():
            return None
            
        pqc_info = {}
        for algo_name, oid in PQC_OIDS.items():
            if oid in self.get_all_oids():
                pqc_info[algo_name] = {
                    'oid': oid,
                    'extensions': self.get_extension(oid)
                }
        return pqc_info

    @property
    def validation_results(self) -> Dict[str, Dict[str, Any]]:
        """Get all validation results"""
        return self._validation_results

    def add_validation_result(self, validator_name: str, is_valid: bool, message: str):
        """Add a validation result
        
        Args:
            validator_name: Name of the validator
            is_valid: Whether the validation passed
            message: Validation message or error
        """
        self._validation_results[validator_name] = {
            'valid': is_valid,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        logger.debug(f"Added validation result for {validator_name}: {is_valid}")

    def is_valid(self) -> bool:
        """Check if all validations passed
        
        Returns:
            bool: True if all validations passed, False otherwise
        """
        return all(result['valid'] for result in self._validation_results.values())

    def get_validation_summary(self) -> Dict[str, Any]:
        """Get a summary of all validation results
        
        Returns:
            dict: Summary of validation results including overall status
        """
        return {
            'overall_valid': self.is_valid(),
            'validations': self._validation_results,
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.not_valid_before.isoformat(),
            'valid_until': self.not_valid_after.isoformat(),
            'serial_number': str(self.serial_number)
        }

    def get_extension(self, oid: x509.ObjectIdentifier) -> Optional[x509.Extension]:
        """Get a certificate extension by OID
        
        Args:
            oid: The extension's Object Identifier
            
        Returns:
            Optional[x509.Extension]: The extension if found, None otherwise
        """
        try:
            return self.x509_cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return None

    def get_public_key(self):
        """Get the certificate's public key"""
        if self.x509_cert:
            return self.x509_cert.public_key()
        return None

    def __str__(self) -> str:
        """String representation of the certificate"""
        return f"Certificate(subject={self.subject}, issuer={self.issuer})"
    
    def get_issuer_name(self):
        """Get the issuer name of the certificate"""
        return self.x509_cert.issuer.rfc4514_string()

    def get_subject_name(self):
        """Get the subject name of the certificate"""
        return self.x509_cert.subject.rfc4514_string()

    def get_serial_number(self):
        """Get the serial number of the certificate"""
        return self.x509_cert.serial_number
    
    def get_validity_period(self):
        """Get the validity period of the certificate"""
        return {
            'valid_from': self.not_valid_before.isoformat(),
            'valid_until': self.not_valid_after.isoformat()
        }
    
    def get_signature(self):
        """Get the signature of the certificate"""
        return self.x509_cert.signature
    
    def get_signature_algorithm(self):  
        """Get the signature algorithm of the certificate"""
        if self.x509_cert:
            return self.x509_cert.signature_algorithm_oid
        return None
    
    def get_version(self):
        """Get the version of the certificate"""
        return self.x509_cert.version  
    
    def get_extensions(self):
        """Get the extensions of the certificate"""
        return self.x509_cert.extensions
    
    def get_extension_oids(self):   
        """Get the OIDs of the extensions of the certificate"""
        return [extension.oid for extension in self.x509_cert.extensions]

    def get_extension_values(self):
        """Get the values of the extensions of the certificate"""
        return {extension.oid: extension.value for extension in self.x509_cert.extensions}
    
    def get_extension_critical(self):   
        """Get the criticality of the extensions of the certificate"""
        return {extension.oid: extension.critical for extension in self.x509_cert.extensions}
    
    # Add compatibility properties for UTC dates
    @property
    def not_valid_before_utc(self):
        """Get the not_valid_before date in UTC (compatibility with x509.Certificate)"""
        return self.not_valid_before
        
    @property
    def not_valid_after_utc(self):
        """Get the not_valid_after date in UTC (compatibility with x509.Certificate)"""
        return self.not_valid_after

