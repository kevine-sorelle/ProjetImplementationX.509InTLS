import pytest
from unittest.mock import Mock, patch
from adaptator.CertificateAdapter import CertificateAdapter
from adaptator.HostnameCertificateAdapter import HostnameCertificateAdapter
from adaptator.FileCertificateAdapter import FileCertificateAdapter
from adaptator.CertificateAdapterFactory import CertificateAdapterFactory
from models.SSLConnectionManager import SSLConnectionManager
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.getCertificate import GetCertificate


"""Test cases for certificate adapters"""
class TestCertificateAdapter:

    @pytest.fixture
    def mock_ssl_manager(self):
        return Mock(spec=SSLConnectionManager)

    @pytest.fixture
    def mock_ssl_fetcher(self):
        return Mock(spec=SSLCertificateFetcher)

    @pytest.fixture
    def mock_cert_retriever(self):
        return Mock(spec=GetCertificate)

    @pytest.fixture
    def mock_certificate_file(self):
        mock_file = Mock()
        mock_file.read.return_value = b"-----BEGIN CERTIFICATE-----\nMOCK CERTIFICATE\n-----END CERTIFICATE-----"
        mock_file.filename = "test_cert.pem"
        return mock_file

    def test_hostname_adapter_retrieval(self, mock_ssl_manager, mock_ssl_fetcher, mock_cert_retriever):
        """Test hostname adapter certificate retrieval"""
        """Arrange"""
        # Setup
        hostname = "example.com"
        port = 443
        expected_cert = "MOCK CERTIFICATE"
        
        # Mock the certificate retrieval
        mock_cert_retriever.get_certificate.return_value = expected_cert
        """Act"""
        # Create adapter
        adapter = HostnameCertificateAdapter(hostname, port)
        adapter.ssl_manager = mock_ssl_manager
        adapter.ssl_fetcher = mock_ssl_fetcher
        adapter.cert_retriever = mock_cert_retriever
        
        # Test
        certificate = adapter.get_certificate()
        source_info = adapter.get_source_info()
        
        # Assertions
        assert certificate == expected_cert
        assert source_info['type'] == 'hostname'
        assert source_info['hostname'] == hostname
        assert source_info['port'] == port
        mock_cert_retriever.get_certificate.assert_called_once_with(hostname, port)

    def test_file_adapter_retrieval(self, mock_certificate_file):
        """Test file adapter certificate retrieval"""
        # Setup
        expected_cert = "-----BEGIN CERTIFICATE-----\nMOCK CERTIFICATE\n-----END CERTIFICATE-----"
        
        # Create adapter
        adapter = FileCertificateAdapter(mock_certificate_file)
        
        # Test
        certificate = adapter.get_certificate()
        source_info = adapter.get_source_info()
        
        # Assertions
        assert certificate == expected_cert
        assert source_info['type'] == 'file'
        assert source_info['filename'] == "test_cert.pem"
        mock_certificate_file.read.assert_called_once()

    def test_adapter_factory_creation(self):
        """Test adapter factory creation"""
        # Test hostname adapter creation
        hostname_adapter = CertificateAdapterFactory.create_adapter(
            'hostname',
            hostname='example.com',
            port=443
        )
        assert isinstance(hostname_adapter, HostnameCertificateAdapter)
        assert hostname_adapter.hostname == 'example.com'
        assert hostname_adapter.port == 443
        
        # Test file adapter creation
        mock_file = Mock()
        file_adapter = CertificateAdapterFactory.create_adapter(
            'file',
            certificate_file=mock_file
        )
        assert isinstance(file_adapter, FileCertificateAdapter)
        assert file_adapter.certificate_file == mock_file
        
        # Test invalid adapter type
        with pytest.raises(ValueError):
            CertificateAdapterFactory.create_adapter('invalid_type')

    def test_adapter_error_handling(self, mock_ssl_manager, mock_ssl_fetcher, mock_cert_retriever, mock_certificate_file):
        """Test error handling in adapters"""
        # Test hostname adapter error
        mock_cert_retriever.get_certificate.side_effect = Exception("Connection failed")
        adapter = HostnameCertificateAdapter("example.com", 443)
        adapter.ssl_manager = mock_ssl_manager
        adapter.ssl_fetcher = mock_ssl_fetcher
        adapter.cert_retriever = mock_cert_retriever
        
        with pytest.raises(Exception) as exc_info:
            adapter.get_certificate()
        assert str(exc_info.value) == "Connection failed"
        
        # Test file adapter error
        mock_certificate_file.read.side_effect = Exception("File read error")
        adapter = FileCertificateAdapter(mock_certificate_file)
        
        with pytest.raises(Exception) as exc_info:
            adapter.get_certificate()
        assert str(exc_info.value) == "File read error"
