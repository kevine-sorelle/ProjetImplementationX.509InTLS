import pytest
from cryptography import x509

from src.strategy.ECDSASignatureStrategy import ECDSASignatureStrategy
from src.models.certificat import Certificat
from src.strategy.RSASignatureStrategy import RSASignatureStrategy

# Helper function to create a test certificate
def load_test_certificate(filename: str) -> x509.Certificate:
    with open(filename, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())

# Fixtures
@pytest.fixture
def test_leaf_certificate():
    cert = load_test_certificate("tests/certs/google_cert_chain.pem")
    return cert

@pytest.fixture
def test_root_certificate():
    cert = load_test_certificate("tests/certs/google_cert_root.pem")
    return cert

@pytest.fixture
def test_root_certificate_rsa():
    cert = load_test_certificate("tests/certs/facebook_cert_root_rsa.pem")
    return cert

@pytest.fixture
def test_leaf_certificate_rsa():
    cert = load_test_certificate("tests/certs/facebook_cert_chain_rsa.pem")
    return cert

def test_ecdsa_signature_strategy(test_leaf_certificate, test_root_certificate):
    # Arrange
    strategy = ECDSASignatureStrategy()

    # Act
    result, message = strategy.validate_signature(test_leaf_certificate, test_root_certificate)

    # Assert
    assert result is True
    assert "valid" in message.lower()
def test_ecdsa_signature_strategy_invalid_issuer_certificate(test_root_certificate):
    # Arrange
    strategy = ECDSASignatureStrategy()
    invalid_issuer = test_root_certificate

    # Act
    result, message = strategy.validate_signature(invalid_issuer, test_root_certificate)

    # Assert
    assert result is False
    assert any(word in message.lower() for word in ["invalid", "does not match", "mismatch"])

def test_ecdsa_signature_strategy_invalid_leaf_certificate(test_leaf_certificate):
    # Arrange
    strategy = ECDSASignatureStrategy()
    invalid_root = test_leaf_certificate

    # Act
    result, message = strategy.validate_signature(test_leaf_certificate, invalid_root)

    # Assert
    assert result is False
    assert any(word in message.lower() for word in ["invalid", "does not match", "mismatch"])

def test_rsa_signature_strategy(test_leaf_certificate_rsa, test_root_certificate_rsa):
    # Arrange
    strategy = RSASignatureStrategy()

    # Act
    result, message = strategy.validate_signature(test_leaf_certificate_rsa, test_root_certificate_rsa)

    # Assert
    assert result is True
    assert "valid" in message.lower()

def test_rsa_signature_strategy_invalid_issuer_certificate(test_root_certificate_rsa):
    # Arrange
    strategy = RSASignatureStrategy()
    invalid_issuer = test_root_certificate_rsa

    # Act
    result, message = strategy.validate_signature(invalid_issuer, test_root_certificate_rsa)

    # Assert
    assert result is False  
    assert any(word in message.lower() for word in ["invalid", "does not match", "mismatch"])

def test_ecdsa_strategy_fail_on_rsa_certificate(test_leaf_certificate_rsa, test_root_certificate):
    # Arrange
    strategy = ECDSASignatureStrategy()

    # Act
    result, message = strategy.validate_signature(test_leaf_certificate_rsa, test_root_certificate)

    # Assert
    assert result is False
    assert any(word in message.lower() for word in ["invalid", "does not match", "mismatch"])

def test_rsa_strategy_fail_on_ecdsa_certificate(test_leaf_certificate, test_root_certificate_rsa):
    # Arrange
    strategy = RSASignatureStrategy()

    # Act
    result, message = strategy.validate_signature(test_leaf_certificate, test_root_certificate_rsa)

    # Assert
    assert result is False
