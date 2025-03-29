"""Concrete implementations of PQC signature validators."""
from typing import Optional, Dict, Type
from models.validation.ISignatureValidator import ISignatureValidator
from models.certificat import Certificat
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class DilithiumValidator(ISignatureValidator):
    """Validator for Dilithium signatures"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            # Placeholder for Dilithium-specific validation logic
            # This would be implemented when the actual Dilithium implementation is needed
            raise NotImplementedError("Dilithium validation not yet implemented")
        except Exception as e:
            cert.add_validation_result('signature_dilithium', False, f"Dilithium validation failed: {str(e)}")
            return False

class FalconValidator(ISignatureValidator):
    """Validator for Falcon signatures"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            # Placeholder for Falcon-specific validation logic
            # This would be implemented when the actual Falcon implementation is needed
            raise NotImplementedError("Falcon validation not yet implemented")
        except Exception as e:
            cert.add_validation_result('signature_falcon', False, f"Falcon validation failed: {str(e)}")
            return False

class SPHINCSPlusValidator(ISignatureValidator):
    """Validator for SPHINCS+ signatures"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            # Placeholder for SPHINCS+-specific validation logic
            # This would be implemented when the actual SPHINCS+ implementation is needed
            raise NotImplementedError("SPHINCS+ validation not yet implemented")
        except Exception as e:
            cert.add_validation_result('signature_sphincs', False, f"SPHINCS+ validation failed: {str(e)}")
            return False

class PQCValidatorFactory:
    """Factory for creating PQC-specific validators"""
    
    _validators: Dict[str, Type[ISignatureValidator]] = {
        'dilithium': DilithiumValidator,
        'falcon': FalconValidator,
        'sphincs': SPHINCSPlusValidator
    }
    
    @classmethod
    def create_validator(cls, algo_name: str) -> ISignatureValidator:
        """Create appropriate validator for PQC algorithm"""
        validator_class = cls._validators.get(algo_name.lower())
        if not validator_class:
            raise ValueError(f"No validator available for PQC algorithm: {algo_name}")
        return validator_class()

class ConcretePQCSignatureValidator(ISignatureValidator):
    """Concrete implementation of PQC signature validator that uses algorithm-specific validators"""
    
    def validate(self, cert: Certificat, issuer_cert: Optional[Certificat] = None) -> bool:
        try:
            pqc_info = cert.get_pqc_algorithm_info()
            if not pqc_info:
                cert.add_validation_result('signature_pqc', False, "No PQC algorithm information found")
                return False
                
            for algo_name in pqc_info:
                try:
                    validator = PQCValidatorFactory.create_validator(algo_name)
                    if not validator.validate(cert, issuer_cert):
                        return False
                except NotImplementedError:
                    # Log that this algorithm is not yet implemented
                    logger.warning(f"PQC algorithm {algo_name} not yet implemented")
                    continue
                    
            cert.add_validation_result('signature_pqc', True, "PQC signature validation successful")
            return True
            
        except Exception as e:
            cert.add_validation_result('signature_pqc', False, f"PQC signature validation failed: {str(e)}")
            return False 