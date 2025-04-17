from typing import Dict, Type
import sys
sys.path.append("src")

from models.validatorInterface import ValidatorInterface
from models.SignatureValidator import SignatureValidator
from models.KeyValidator import KeyValidator
from models.IssuerValidator import IssuerValidator
from models.DateValidator import DateValidator
from models.RevocationValidator import RevocationValidator
from models.ExtensionValidator import ExtensionValidator
from models.AlgorithmValidator import AlgorithmValidator
from models.SubjectValidator import SubjectValidator

class ValidatorFactory:
    _validators: Dict[str, Type[ValidatorInterface]] = {
        'signature': SignatureValidator,
        'key': KeyValidator,
        'issuer': IssuerValidator,
        'date': DateValidator,
        'revocation': RevocationValidator,
        'extension': ExtensionValidator,
        'algorithm': AlgorithmValidator,
        'subject': SubjectValidator
    }

    @classmethod
    def create_validator(cls, validator_type: str, *args, **kwargs) -> ValidatorInterface:
        """Create a validator instance based on the type"""
        validator_class = cls._validators.get(validator_type.lower())
        if not validator_class:
            raise ValueError(f"Unknown validator type: {validator_type}")
        return validator_class(*args, **kwargs)

    @classmethod
    def get_available_validators(cls) -> list[str]:
        """Get list of all available validator types"""
        return list(cls._validators.keys()) 