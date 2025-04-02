import pytest
from datetime import datetime, timedelta

from src.models.DateValidator import DateValidator
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.Validator import Validator
from src.models.ValidatorDeBase import ValidatorDeBase
from src.models.getCertificate import GetCertificate


@pytest.fixture()
def setup():
    validator_date = DateValidator(ValidatorDeBase())
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    get_certificate = GetCertificate(connection, fetcher)
    cert_pem = get_certificate.get_certificate(connection.hostname, connection.port)

    return validator_date, cert_pem

def test_certificate_date_validity(setup):
    # Arrange
    d_validator, cert_pem = setup

    # Act
    result = d_validator.validate(cert_pem)

    # Assert
    assert result is True

def test_get_validity_period(setup):
    # Arrange
    validator_d, cert_pem = setup

    # Act
    result = validator_d.getValidityPeriod(cert_pem)

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
    validator_date, cert_pem = setup

    # Act
    result = validator_date.getValidityPeriod(cert_pem)

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
