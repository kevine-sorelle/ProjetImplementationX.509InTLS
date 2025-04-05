import pytest
from src.models.Validator import Validator
from src.models.ValidatorFactory import ValidatorFactory
from src.models.ValidationStrategy import ValidationStrategy
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.getCertificate import GetCertificate


@pytest.fixture
def test_certificate():
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    getter = GetCertificate(connection, fetcher)
    cert = getter.get_certificate(connection.hostname, connection.port)
    return cert

@pytest.fixture
def setup(test_certificate):
    list_validators = ["signature", "key", "issuer", "date", "revocation", "extension", "algorithm"]
    strategy = ValidationStrategy(list_validators)
    return strategy, test_certificate

def test_signature_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'signature' in result, "Signature validation result should be present"
    assert result['signature']['valid'] is True, f"Signature validation failed: {result['signature']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}"       

def test_key_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'key' in result, "Key validation result should be present"
    assert result['key']['valid'] is True, f"Key validation failed: {result['key']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}"       

def test_issuer_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)    

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'issuer' in result, "Issuer validation result should be present"
    assert result['issuer']['valid'] is True, f"Issuer validation failed: {result['issuer']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}"       

def test_date_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'signature' in result, "Signature validation result should be present"
    assert result['signature']['valid'] is True, f"Signature validation failed: {result['signature']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}"       

def test_revocation_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'revocation' in result, "Revocation validation result should be present"
    assert result['revocation']['valid'] is True, f"Revocation validation failed: {result['revocation']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}"       

def test_extension_validator(setup):
    # Arrange
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'extension' in result, "Extension validation result should be present"
    assert result['extension']['valid'] is True, f"Extension validation failed: {result['extension']['message']}"
    # Check that all validators passed
    for validator_name, validation_result in result.items():
        assert validation_result['valid'] is True, f"{validator_name} validation failed: {validation_result['message']}" 

def test_algorithm_validator(setup):
    # Arrange
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'algorithm' in result, "Algorithm validation result should be present"
    assert result['algorithm']['valid'] is True, f"Algorithm validation failed: {result['algorithm']['message']}"
    
