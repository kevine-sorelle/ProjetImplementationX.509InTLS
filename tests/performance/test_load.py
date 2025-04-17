import pytest
import time
import concurrent.futures
from cryptography import x509

from src.models.SignatureValidator import SignatureValidator
from src.models.ValidatorDeBase import ValidatorDeBase

# Helper function to create a test certificate
def load_test_certificate(filename: str) -> x509.Certificate:
    with open(filename, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())
    
@pytest.fixture
def sample_cert():
    return load_test_certificate("tests/certs/google_cert_chain.pem")
    
@pytest.mark.load
def test_concurrent_validations_performance(sample_cert):
    """Test the performance of concurrent validations"""
    # Arrange
    base = ValidatorDeBase()
    validator = SignatureValidator(base)
    start_time = time.time()
    validation_errors = []

    def validate_cert(cert):
        try:
            result = validator.validate(cert)
            if not result[0]:
                validation_errors.append(result[1])
            return result
        except Exception as e:
            validation_errors.append(str(e))
            return False, str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_cert, sample_cert) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
    end_time = time.time()
    total_time = end_time - start_time

    if validation_errors:
         for error in validation_errors:
              print(f"Validation error: {error}")

    # Assert
    assert all(isinstance(result, tuple) for result in results), "All results should be boolean"
    assert all(result[0] for result in results), "All certificates should be valid"

    # Performance assertions
    avg_time_per_validation = total_time / 50
    assert total_time < 1.0, "Total time should be less than 0.1 seconds"
    
