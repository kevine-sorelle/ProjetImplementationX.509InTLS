import pytest
import datetime
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.analyseCertificate import AnalyseCertificate
from src.models.getCertificate import GetCertificate


@pytest.fixture
def setup():
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    get_certificate = GetCertificate(connection, fetcher) # Récupération du certificat
    cert_pem = get_certificate.get_certificate("google.com")  # Updated method name and added hostname
    return cert_pem

def test_analyse_certificate(setup):
    # Arrange
    cert_pem = setup
    # cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    analyser = AnalyseCertificate()
    expected_result = {
        'is_valid': True,
        'issuer': 'CN=WE2,O=Google Trust Services,C=US',
        'subject': 'CN=*.google.com',
        'validity_period': {
            'valid_from': datetime.datetime(2025, 2, 26, 15, 33, 3, tzinfo=datetime.timezone.utc),
            'valid_to': datetime.datetime(2025, 5, 21, 15, 33, 2, tzinfo=datetime.timezone.utc),
        }
    }

    # Act
    result = analyser.analyseCertificate(cert_pem)

    # Assert validity
    assert result['is_valid'] == expected_result['is_valid']

    # Assert subject
    assert result['subject'] == expected_result['subject']

    # Assert datetime fields are approximately equal
    """assert CalculateDate.approximately_equal_datetime(result['validity_period']['valid_from'],
          expected_result['validity_period']['valid_from'])
    assert CalculateDate.approximately_equal_datetime(result['validity_period']['valid_to'],
                        expected_result['validity_period']['valid_to'])"""

