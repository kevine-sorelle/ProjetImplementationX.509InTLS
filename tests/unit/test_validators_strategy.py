import pytest
from src.models.Validator import Validator
from src.models.ValidatorFactory import ValidatorFactory
from src.models.ValidationStrategy import ValidationStrategy
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.getCertificate import GetCertificate
from cryptography import x509


@pytest.fixture
def test_certificate():
   with open("tests/certs/google_cert_chain.pem", "rb") as cert_file:
       cert_data = cert_file.read()
       return x509.load_pem_x509_certificate(cert_data)

@pytest.fixture
def test_issuer_certificate():
    with open("tests/certs/google_cert_root.pem", "rb") as cert_file:
        cert_data = cert_file.read()
        return x509.load_pem_x509_certificate(cert_data)

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
    assert isinstance(result['signature']['message'], str), "Message should be a string"

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
    assert isinstance(result['key']['message'], str), "Message should be a string"

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
    assert isinstance(result['issuer']['message'], str), "Message should be a string"

def test_date_validator(setup):
    # Arrange   
    strategy = setup[0]
    certificate = setup[1]

    # Act
    result = strategy.validate_certificate(certificate)

    # Assert    
    assert isinstance(result, dict), "Result should be a dictionary"
    assert 'date' in result, "Date validation result should be present"
    assert result['date']['valid'] is True, f"Date validation failed: {result['date']['message']}"
    assert isinstance(result['date']['message'], str), "Message should be a string"

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
    assert isinstance(result['revocation']['message'], str), "Message should be a string"

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
    assert isinstance(result['extension']['message'], str), "Message should be a string"

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
    assert isinstance(result['algorithm']['message'], str), "Message should be a string"
