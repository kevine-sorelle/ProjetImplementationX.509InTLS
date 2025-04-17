import pytest

from src.models.IssuerValidator import IssuerValidator
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.ValidatorDeBase import ValidatorDeBase
from src.models.getCertificate import GetCertificate


@pytest.fixture()
def setup():
    issuer_validator = IssuerValidator(ValidatorDeBase())
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    get_certificate = GetCertificate(connection, fetcher)
    cert_pem = get_certificate.get_certificate(connection.hostname, connection.port)

    return cert_pem, issuer_validator

def test_get_issuer(setup):
    # Arrange
    cert_pem, issuer_validator = setup
    '''Only validate that the issuer has
       the organization "Google Trust Services
    '''
    # "O": Org, "C": Country
    expected_issuer_parts = {"O": "Google Trust Services", "C": "US"}

    # Act
    issuer = issuer_validator.getIssuer(cert_pem)
    is_valid, message = issuer_validator.validate(cert_pem)

    # Debugging actual issuer
    print(f"Actual issuer: {issuer}")

    # Parse the issuer string into a dictionary
    issuer_parts = dict(part.split("=") for part in issuer.split(","))
    print(f"Issuer parts: {issuer_parts}")

    # Assert
    assert is_valid is True
    assert issuer is not None
    assert "successful" in message
    for key, value in expected_issuer_parts.items():
        assert issuer_parts.get(key) == value, \
            f"Expected '{key}={value}' but got '{issuer_parts.get(key)}'"
