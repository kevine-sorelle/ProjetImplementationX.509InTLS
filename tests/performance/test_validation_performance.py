import time
import pytest
from cryptography import x509
from src.models.SignatureValidator import SignatureValidator
from src.models.ValidatorDeBase import ValidatorDeBase
from src.services.IssuerCertificateFetcher import IssuerCertificateFetcher


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

@pytest.mark.performance
def test_signature_validation_performance(sample_cert):
    # Arrange
    base = ValidatorDeBase()
    validator = SignatureValidator(base)

    # Act
    start_time = time.time()
    for _ in range(100): # 100 itérations pour avoir un temps significatif
        validator.validate(sample_cert)
    end_time = time.time()
    avg_time = (end_time - start_time) / 100

    # Assert
    assert avg_time < 0.2 # Temps d'exécution inférieur à 0.1 secondes  


@pytest.mark.performance
def test_certificate_fetcher_caching(sample_cert):
    """First fetch is slow, but subsequent fetches are cached"""
    # Arrange
    start_time = time.time()
    # Act - First fetch
    first_fetch = IssuerCertificateFetcher.get_issuer_certificate(sample_cert)
    first_fetch_time = time.time() - start_time

    time.sleep(3)

    """Subsequent fetches should be faster"""
    # Act - Subsequent fetch
    start_time = time.time()
    second_fetch = IssuerCertificateFetcher.get_issuer_certificate(sample_cert)
    second_fetch_time = time.time() - start_time

    # Assert
    assert first_fetch is not None
    assert second_fetch is not None
    assert first_fetch == second_fetch
    assert second_fetch_time < first_fetch_time, (
        f"Cache did not improve performance."
        f"First fetch time: {first_fetch_time:.4f} seconds"
        f"Second fetch time: {second_fetch_time:.4f} seconds"
    )


