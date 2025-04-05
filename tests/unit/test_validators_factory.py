import pytest
from src.models.Validator import Validator
from src.models.ValidatorFactory import ValidatorFactory
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.getCertificate import GetCertificate
from src.models.ValidatorDeBase import ValidatorDeBase

@pytest.fixture
def test_certificate():
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    getter = GetCertificate(connection, fetcher)
    cert = getter.get_certificate(connection.hostname, connection.port)
    return cert


@pytest.fixture
def setup(test_certificate):
    validator_factory = ValidatorFactory()
    base_validator = ValidatorDeBase()
    validator_signature = validator_factory.create_validator("signature", base_validator)
    validator_key = validator_factory.create_validator("key", base_validator)
    validator_revocation = validator_factory.create_validator("revocation", base_validator)
    validator_extension = validator_factory.create_validator("extension", base_validator)
    validator_issuer = validator_factory.create_validator("issuer", base_validator)
    validator_date = validator_factory.create_validator("date", base_validator)
    validator_algorithm = validator_factory.create_validator("algorithm", base_validator)
    return validator_signature, validator_key, validator_revocation, validator_extension, validator_issuer, validator_date, validator_algorithm, test_certificate

def test_signature_validator(setup):
    # Arrange
    validator = setup[0]
    certificate = setup[7]

    # Act
    result, message  = validator.validate(certificate)

    # Assert
    assert result is True


def test_key_validator(setup):
    # Arrange
    validator = setup[1]
    certificate = setup[7]

    # Act
    result, message  = validator.validate(certificate)

    # Assert
    assert result is True

def test_revocation_validator(setup):
    # Arrange
    validator = setup[2]
    certificate = setup[7]  

    # Act
    result, message  = validator.validate(certificate)

    # Assert
    assert result is True

def test_extension_validator(setup):
    # Arrange
    validator = setup[3]
    certificate = setup[7]

    # Act
    result, message = validator.validate(certificate)

    # Assert    
    assert result is True

def test_issuer_validator(setup):
    # Arrange
    validator = setup[4]
    certificate = setup[7]

    # Act
    result = validator.validate(certificate)

    # Assert
    assert result is True

def test_date_validator(setup):
    # Arrange
    validator = setup[5]
    certificate = setup[7]

    # Act
    result = validator.validate(certificate)    

    # Assert    
    assert result is True



def test_algorithm_validator(setup):
    # Arrange
    validator = setup[6]
    certificate = setup[7]

    # Act
    is_valid, message = validator.validate(certificate)

    # Assert
    assert is_valid, f"Algorithm validation failed: {message}"






