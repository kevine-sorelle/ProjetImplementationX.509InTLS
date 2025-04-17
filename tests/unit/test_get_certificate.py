import pytest

from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.analyseCertificate import AnalyseCertificate
from src.models.getCertificate import GetCertificate


@pytest.fixture()
def setup():
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    return connection, fetcher


def test_get_certificate(setup):
    # Arrange
    connection, fetcher = setup
    cert_retriever = GetCertificate(connection, fetcher)

    # Act
    result = cert_retriever.get_certificate(connection.hostname, connection.port)


    # Assert
    assert isinstance(result, str)
    assert "BEGIN CERTIFICATE" in result  # Ensure the response is a valid PEM certificate