"""Concrete implementations of signature validators."""
from typing import Optional, Dict, Type
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from utils.logger_config import setup_logger
from models.certificat import Certificat, CertificateType
from models.validation.ISignatureValidator import ISignatureValidator

logger = setup_logger(__name__)

class TraditionalSignatureValidator(ISignatureValidator):
    """Validator for traditional RSA/ECDSA signatures"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            public_key = issuer_cert.get_public_key() if issuer_cert else cert.get_public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    cert.get_signature(),
                    cert.x509_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.get_signature_algorithm()
                )
            elif isinstance(public_key, EllipticCurvePublicKey):
                public_key.verify(
                    cert.get_signature(),
                    cert.x509_cert.tbs_certificate_bytes,
                    ECDSA(cert.get_signature_algorithm())
                )
            else:
                raise ValueError(f"Unsupported key type: {type(public_key).__name__}")
                
            cert.add_validation_result('signature_traditional', True, "Traditional signature validation successful")
            return True
            
        except Exception as e:
            cert.add_validation_result('signature_traditional', False, f"Traditional signature validation failed: {str(e)}")
            return False

class PQCSignatureValidatorAdapter(ISignatureValidator):
    """Base adapter for PQC signature validation"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            pqc_info = cert.get_pqc_algorithm_info()
            if not pqc_info:
                cert.add_validation_result('signature_pqc', False, "No PQC algorithm information found")
                return False
                
            # Delegate to specific PQC validator based on algorithm
            for algo_name, info in pqc_info.items():
                validator = self._get_pqc_validator(algo_name)
                if not validator.validate(cert, issuer_cert):
                    return False
                    
            cert.add_validation_result('signature_pqc', True, "PQC signature validation successful")
            return True
            
        except Exception as e:
            cert.add_validation_result('signature_pqc', False, f"PQC signature validation failed: {str(e)}")
            return False
            
    def _get_pqc_validator(self, algo_name: str) -> ISignatureValidator:
        """Factory method to get specific PQC validator"""
        # This will be implemented by concrete PQC validator adapters
        raise NotImplementedError(f"Validator for {algo_name} not implemented")

class HybridSignatureValidatorAdapter(ISignatureValidator):
    """Adapter for hybrid signature validation"""
    
    def __init__(self, validation_strategy: str = "all"):
        """Initialize with validation strategy
        
        Args:
            validation_strategy: How to validate hybrid signatures
                               "all" - all signatures must be valid
                               "any" - any signature must be valid
                               "traditional_first" - traditional must be valid, PQC optional
                               "pqc_first" - PQC must be valid, traditional optional
        """
        self.validation_strategy = validation_strategy
        self.traditional_validator = TraditionalSignatureValidator()
        self.pqc_validator = PQCSignatureValidatorAdapter()
        
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            traditional_valid = self.traditional_validator.validate(cert, issuer_cert)
            pqc_valid = self.pqc_validator.validate(cert, issuer_cert)
            
            result = self._apply_strategy(traditional_valid, pqc_valid)
            message = self._get_validation_message(traditional_valid, pqc_valid)
            
            cert.add_validation_result('signature_hybrid', result, message)
            return result
            
        except Exception as e:
            cert.add_validation_result('signature_hybrid', False, f"Hybrid signature validation failed: {str(e)}")
            return False
            
    def _apply_strategy(self, traditional_valid: bool, pqc_valid: bool) -> bool:
        """Apply the validation strategy"""
        strategies = {
            "all": lambda: traditional_valid and pqc_valid,
            "any": lambda: traditional_valid or pqc_valid,
            "traditional_first": lambda: traditional_valid,
            "pqc_first": lambda: pqc_valid
        }
        return strategies.get(self.validation_strategy, strategies["all"])()
        
    def _get_validation_message(self, traditional_valid: bool, pqc_valid: bool) -> str:
        """Generate validation message based on results"""
        return (f"Hybrid validation ({self.validation_strategy}): "
                f"Traditional: {'✓' if traditional_valid else '✗'}, "
                f"PQC: {'✓' if pqc_valid else '✗'}")

class SignatureValidatorFactory:
    """Factory for creating appropriate signature validators"""
    
    _validators: Dict[CertificateType, Type[ISignatureValidator]] = {
        CertificateType.TRADITIONAL: TraditionalSignatureValidator,
        CertificateType.PQC: PQCSignatureValidatorAdapter,
        CertificateType.HYBRID: HybridSignatureValidatorAdapter
    }
    
    @classmethod
    def create_validator(cls, cert_type: CertificateType, **kwargs) -> ISignatureValidator:
        """Create appropriate validator for certificate type"""
        validator_class = cls._validators.get(cert_type)
        if not validator_class:
            raise ValueError(f"No validator available for certificate type: {cert_type}")
        return validator_class(**kwargs) 