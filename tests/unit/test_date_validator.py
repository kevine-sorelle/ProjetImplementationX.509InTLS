import pytest
from cryptography import x509

from src.models.DateValidator import DateValidator
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.getCertificate import GetCertificate


@pytest.fixture()
def setup():
    date_validator = DateValidator()
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    get_certificate = GetCertificate(connection, fetcher)
    cert_pem = get_certificate.getCertificate()

    return date_validator, cert_pem

def test_check_certificate_validity(setup):
    # Arrange
    d_validator, cert_pem = setup

    # Act
    result = d_validator.checkCertificateValidity(cert_pem)

    # Assert
    assert result is True