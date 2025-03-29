from typing import List
import sys
sys.path.append("src")

from models.validatorInterface import ValidatorInterface
from models.ValidatorFactory import ValidatorFactory
from models.Validator import Validator
from models.ValidatorDeBase import ValidatorDeBase

class ValidationStrategy:
    def __init__(self, validator_types: List[str]):
        """Initialize with list of validator types to use"""
        self.validators = []
        factory = ValidatorFactory()
        base_validator = ValidatorDeBase()
        
        # Create validators using both approaches
        for v_type in validator_types:
            try:
                # Create the specific validator with base validator
                new_validator = factory.create_validator(v_type, base_validator)
                # Wrap it in the Validator class for consistency with AnalyseCertificate
                wrapped_validator = Validator(new_validator)
                self.validators.append(wrapped_validator)
            except ValueError as e:
                print(f"Warning: {str(e)}")

    def validate_certificate(self, certificate) -> dict:
        """Run all validations and return results"""
        results = {}
        
        if not self.validators:
            return results
            
        for validator in self.validators:
            try:
                result = validator.validate(certificate)
                # Handle both tuple returns (new style) and direct returns (old style)
                if isinstance(result, tuple):
                    is_valid, message = result
                else:
                    is_valid = bool(result)
                    message = "Validation successful" if is_valid else "Validation failed"
                
                validator_name = validator.validator.__class__.__name__.replace('Validator', '')
                results[validator_name.lower()] = {
                    'valid': is_valid,
                    'message': message
                }
            except Exception as e:
                results['error'] = {
                    'valid': False,
                    'message': str(e)
                }
        
        return results 