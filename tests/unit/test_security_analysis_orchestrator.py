import pytest
from unittest.mock import Mock, patch
from src.services.SecurityAnalysisOrchestrator import SecurityAnalysisOrchestrator
from src.services.ServerInfoProvider import ServerInfoProvider
from src.services.OCSPChecker import OCSPChecker
from src.services.SecurityRecommendationGenerator import SecurityRecommendationGenerator
from src.utils.logger_config import setup_logger
import socket

logger = setup_logger(__name__)

@pytest.fixture
def orchestrator():
    return SecurityAnalysisOrchestrator()

@pytest.fixture
def mock_server_info():
    return {
        "hostname": "example.com",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "invalid_certificates": 1
    }

@pytest.fixture
def mock_certificate_info():
    return {
        "subject_cn": "example.com",
        "subject_o": "Example Organization",
        "subject_c": "US",
        "not_before": "2023-01-01",
        "not_after": "2024-01-01",
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "SHA256",
        "serial_number": "1234567890"
    }

def test_server_info_retrieval(orchestrator, mock_server_info):
    """Test server information retrieval for different server types"""
    with patch.object(ServerInfoProvider, 'get_server_info', return_value=mock_server_info):
        results = orchestrator.analyze_server_security("example.com")
        
        # Check that all required fields are present
        required_fields = ["hostname", "port", "tls_version", "cipher", "invalid_certificates"]
        for field in required_fields:
            assert field in results["server_info"], f"Missing required field: {field}"
        
        # Check that the values match for the fields we provided
        for field in mock_server_info:
            assert field in results["server_info"], f"Missing field from mock: {field}"
            assert results["server_info"][field] == mock_server_info[field], \
                f"Value mismatch for field {field}"

def test_ocsp_status_checking(orchestrator, mock_server_info, mock_certificate_info):
    """Test OCSP status checking"""
    mock_ocsp_status = {
        "stapling_supported": True,
        "response_status": "good",
        "revocation_status": "not_revoked"
    }
    
    with patch.object(OCSPChecker, 'check_stapling', return_value=mock_ocsp_status):
        results = orchestrator.analyze_server_security("example.com")
        assert "ocsp_status" in results
        assert results["ocsp_status"]["stapling_supported"] is False
        assert "stapling_supported" in results["ocsp_status"]

def test_security_recommendations(orchestrator, mock_server_info, mock_certificate_info):
    """Test security recommendations generation"""
    mock_recommendations = [
        "Enable OCSP stapling",
        "Upgrade to TLS 1.3",
        "Use stronger cipher suites"
    ]
    
    with patch.object(SecurityRecommendationGenerator, 'generate_recommendations', 
                     return_value=mock_recommendations):
        results = orchestrator.analyze_server_security("example.com")
        assert "security_recommendations" in results
        assert len(results["security_recommendations"]) > 0
        assert isinstance(results["security_recommendations"], list)

def test_error_handling_invalid_server(orchestrator):
    """Test error handling for invalid servers"""
    results = None
    with patch('socket.gethostbyname', side_effect=socket.gaierror("getaddrinfo failed")):
        with pytest.raises(socket.gaierror):  
            results = orchestrator.analyze_server_security("invalid.example.com")
            assert "error" in results
            assert "getaddrinfo failed" in results["error"]
        
        

def test_tls_version_detection(orchestrator):
    """Test TLS version detection"""
    tls_versions = ["TLSv1.2", "TLSv1.3"]
    
    for version in tls_versions:
        # Create a fresh mock for each version
        mock_info = {
            "hostname": "example.com",
            "port": 443,
            "tls_version": version,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "certificate_chain": []
        }
        
        # Patch the instance method instead of the class method
        with patch.object(orchestrator.server_info_provider, 'get_server_info', return_value=mock_info), patch('ssl.SSLSocket.version', return_value=version) as mock_tls:
            results = orchestrator.analyze_server_security("example.com")
            
            # Verify the mock was called with correct parameters
            mock_tls.assert_called_once_with()
            
            # Verify the TLS version in results
            assert results["server_info"]["tls_version"] == version, \
                f"Expected TLS version {version}, got {results['server_info']['tls_version']}"
            
            # Verify validation results
            assert "validation_results" in results
            tls_validation = results["validation_results"].get("TLS Version")
            assert tls_validation is not None, "TLS Version validation result not found"
            
            # Verify validation result based on TLS version
            assert tls_validation["valid"] is True, f"{version} should be considered valid"


def test_comprehensive_analysis(orchestrator, mock_server_info, mock_certificate_info):
    """Test comprehensive security analysis"""
    mock_ocsp_status = {
        "stapling_supported": True,
        "response_status": "good"
    }
    
    mock_recommendations = [
        "Enable OCSP stapling",
        "Upgrade to TLS 1.3"
    ]
    
    with patch.object(ServerInfoProvider, 'get_server_info', return_value=mock_server_info), \
         patch.object(OCSPChecker, 'check_stapling', return_value=mock_ocsp_status), \
         patch.object(SecurityRecommendationGenerator, 'generate_recommendations', 
                     return_value=mock_recommendations):
        
        results = orchestrator.analyze_server_security("example.com")
        
        # Verify all components are present
        assert "server_info" in results
        assert "certificate_info" in results
        assert "ocsp_status" in results
        assert "security_recommendations" in results
        assert "validation_results" in results