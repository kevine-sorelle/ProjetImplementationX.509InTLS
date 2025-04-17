import sys
sys.path.append("src")
from models.KeyValidator import KeyValidator
from models.OpenSSLParser import OpenSSLParser
from models.SignatureValidator import SignatureValidator
from models.Validator import Validator
from models.ValidatorDeBase import ValidatorDeBase


class SecurityTest:
    def __init__(self):
        self.validator_base = ValidatorDeBase()
        self.signature_validator = SignatureValidator(self.validator_base)
        self.s_validator = Validator(validator=self.signature_validator)
        self.key_validator = KeyValidator(self.validator_base)
        self.k_validator = Validator(validator=self.key_validator)
        self.parser = OpenSSLParser()

    def securityTest(self, cert_pem: str) -> dict:
        cert = self.parser.parse(cert_pem)
        return {
            "signature": self.s_validator.validate(cert),
            "key": self.k_validator.validate(cert)
        }
