import sys
sys.path.append("src")
from models.validatorInterface import ValidatorInterface


class Validator:

   def __init__(self, validator: ValidatorInterface):
       self.validator = validator

   def validate(self, certificate):
       return self.validator.validate(certificate)