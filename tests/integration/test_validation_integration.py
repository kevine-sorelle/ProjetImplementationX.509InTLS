import pytest
from cryptography import x509

from src.builder.SecurityReportBuilder import SecurityReportBuilder
from src.models.SignatureValidator import SignatureValidator
from src.models.ValidatorDeBase import ValidatorDeBase
from src.models.certificat import Certificat
# Helper function to create a test certificate
def load_test_certificate(filename: str) -> x509.Certificate:
    with open(filename, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())

@pytest.fixture
def sample_cert():
    return load_test_certificate("tests/certs/google_cert_chain.pem")

@pytest.fixture
def sample_issuer():
    return load_test_certificate("tests/certs/google_cert_root.pem")

def test_certificate_type_detection(sample_cert):
    # Arrange
    cert = Certificat(sample_cert)

    # Act
    cert_type = cert.certificate_type
    signature_algorithm = cert.get_signature_algorithm()

    # Assert
    assert cert_type is not None
    assert signature_algorithm is not None

def test_certificate_chain_validation(sample_cert, sample_issuer):
    # Arrange
    base = ValidatorDeBase()
    validator = SignatureValidator(base)

    # Act
    is_valid, message = validator.validate(sample_cert)

    # Assert
    assert is_valid is True
    assert message is not None

def test_certificate_creation_and_validation(sample_cert):
    # Arrange
    builder = SecurityReportBuilder()

    # Act
    report = builder.build()
    
    # Assert
    assert report is not None
    assert isinstance(report,   dict)


