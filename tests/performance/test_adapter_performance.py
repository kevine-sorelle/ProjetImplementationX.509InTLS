import pytest
import time
import concurrent.futures
from src.adaptator.CertificateAdapterFactory import CertificateAdapterFactory
from src.adaptator.FileCertificateAdapter import FileCertificateAdapter
from src.adaptator.HostnameCertificateAdapter import HostnameCertificateAdapter
from src.adaptator.CertificateAdapter import CertificateAdapter
from cryptography import x509
from cryptography.hazmat.backends import default_backend

@pytest.fixture(scope="session")
def sample_cert_data():
     return open("tests/certs/google_cert_chain.pem", "rb")

@pytest.fixture(scope="session")
def sample_cert_file_bytes():
    with open("tests/certs/google_cert_chain.pem", "rb") as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

@pytest.fixture(scope="session")
def sample_cert_file(sample_cert_data):
    return x509.load_pem_x509_certificate(sample_cert_data)

@pytest.fixture
def sample_cert_hostname():
    return "www.google.com"

@pytest.fixture
def sample_cert_file():
    return "tests/certs/google_cert_chain.pem"

@pytest.mark.performance
def test_file_adapter_performance(sample_cert_data):
    # Arrange
    """factory = CertificateAdapterFactory()
    adapter = factory.create_adapter(sample_cert_file)"""
    adapter = FileCertificateAdapter(sample_cert_data)
    iterations = 100

    # Act
    start_time = time.time()
    for _ in range(iterations):
        adapter.get_certificate()
    end_time = time.time()
    avg_time = (end_time - start_time) / iterations

    # Assert
    assert avg_time < 0.1 # Temps d'exécution inférieur à 0.1 secondes  


@pytest.mark.performance
def test_hostname_adapter_performance(sample_cert_hostname):
    # Arrange
    adapter = HostnameCertificateAdapter(sample_cert_hostname)
    iterations = 5 

    # Act
    start_time = time.time()
    for _ in range(iterations):
        adapter.get_certificate()
    end_time = time.time()
    avg_time = (end_time - start_time) / iterations

    # Assert
    assert avg_time < 2.0 # Temps d'exécution inférieur à 2 secondes  

@pytest.mark.performance
def test_adapter_factory_performance(sample_cert_file_bytes, sample_cert_hostname):
    # Arrange
    factory = CertificateAdapterFactory()
    iterations = 1000

    # Act
    start_time = time.time()
    for _ in range(iterations):
        factory.create_adapter("file", certificate_file=sample_cert_file_bytes)
        factory.create_adapter("hostname", hostname=sample_cert_hostname)
    end_time = time.time()
    avg_time = (end_time - start_time) / (iterations * 2)

    # Assert
    assert avg_time < 0.0001 # Temps d'exécution inférieur à 0.1 secondes  

def test_concurrent_adapter_usage(sample_cert_data, sample_cert_hostname):
    # Arrange
    file_adapter = FileCertificateAdapter(sample_cert_data)
    hostname_adapter = HostnameCertificateAdapter(sample_cert_hostname)
    
    def process_file():
        return file_adapter.get_certificate()
    
    def process_hostname():
        return hostname_adapter.get_certificate()
    
    # Act
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        file_futures = [executor.submit(process_file) for _ in range(10)]
        hostname_futures = [executor.submit(process_hostname) for _ in range(2)]

    # Wait for all tasks to complete
    all_futures = concurrent.futures.wait(file_futures + hostname_futures)

    # Assert
    for future in file_futures:
        assert future.result() is not None
    for future in hostname_futures:
        assert future.result() is not None


        
#






