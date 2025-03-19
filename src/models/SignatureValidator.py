from src.models.Validator import Validator


class SignatureValidator(Validator):
    def __init__(self, name, value, type, certificate):
        super().__init__(self, name, value, type, certificate)

    def validate(self):
        pass