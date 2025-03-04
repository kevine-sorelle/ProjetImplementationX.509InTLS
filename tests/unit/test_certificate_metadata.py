import pytest
from cryptography import x509
from datetime import datetime, timedelta

from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.certificateMetadata import CertificateMetadata
from src.models.getCertificate import GetCertificate


@pytest.fixture()
def setup():
    c_metadata = CertificateMetadata()
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    get_certificate = GetCertificate(connection, fetcher)
    cert_pem = get_certificate.getCertificate()

    return cert_pem, c_metadata

def test_get_issuer(setup):
    # Arrange
    cert_pem, cert_metadata = setup
    '''Only validate that the issuer has
       the organization "Google Trust Services
    '''
    # "O": Org, "C": Country
    expected_issuer_parts = {"O": "Google Trust Services", "C": "US"}

    # Act
    issuer = cert_metadata.getIssuer(cert_pem)
    is_valid = cert_metadata.validateIssuer(cert_pem, expected_issuer_parts)

    # Debugging actual issuer
    print(f"Actual issuer: {issuer}")

    # Assert
    assert is_valid, f"Issuer '{issuer}' did not match the expected criteria."

def test_get_validity_period(setup):
    # Arrange
    cert_pem, cert_metadata = setup

    # Act
    result = cert_metadata.getValidityPeriod(cert_pem)

    # Assert: Ensure keys are present
    assert "valid_from" in result, ("Missing 'valid_from' "
                                    "key in result")
    assert "valid_to" in result, ("Missing 'valid_to' "
                                  "key in result")

    # Assert: Ensure both values are datetime objects
    assert isinstance(result["valid_from"],
                      datetime),("'valid_from' is not a "
                                 "datetime object")
    assert isinstance(result["valid_to"], datetime), ("'valid_to"
                                    "is not a datetime object")

    # Debugging output for validation
    print(f"Valid from: {result['valid_from']},"
          f"Valid to: {result['valid_to']}")

    # Assert: Ensure validity dates are within a reasonable range
    now = datetime.now(tz=result["valid_from"].tzinfo) # Use timezone-aware datetime
    assert result["valid_from"] <= now, "'valid_from' must be in the past"
    assert result["valid_to"] >= now, "'valid_to' must be in the future"

def test_get_validity_period_with_tolerance(setup):
    # Arrange
    cert_pem, cert_metadata = setup

    # Act
    result = cert_metadata.getValidityPeriod(cert_pem)

    # Assert: Ensure keys are present
    assert "valid_from" in result, "Missing 'valid_from' key in result"
    assert "valid_to" in result, "Missing 'valid_to' key in result"

    # Assert: Ensure both values are datetime objects
    assert isinstance(result["valid_from"],
                      datetime), "'valid_from' is not a datetime object"
    assert isinstance(result["valid_to"],
                      datetime), "'valid_to' is not a datetime object"

    # Assert: Ensure dates are within a given tolerance
    now = datetime.now(tz=result["valid_from"].tzinfo)
    tolerance = timedelta(seconds=10) # Define a 10-second tolerance
    assert result["valid_from"] <= now + tolerance, "'valid_from' must not be in the far future"
    assert result["valid_to"] >= now - tolerance, "'valid_to' must not be in the far past"

