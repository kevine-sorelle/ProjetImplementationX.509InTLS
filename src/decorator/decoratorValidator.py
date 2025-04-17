from abc import abstractmethod
import sys
sys.path.append("src")
from models.validatorInterface import ValidatorInterface


class DecoratorValidator(ValidatorInterface):
    def __init__(self, validator_decoree):
        self.validator_decoree = validator_decoree

    @abstractmethod
    def validate(self, certificate):
        pass