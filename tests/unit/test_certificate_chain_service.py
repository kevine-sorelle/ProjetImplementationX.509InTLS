import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from src.services.CertificateChainService import CertificateChainService
from src.utils.logger_config import setup_logger

logger = setup_logger(__name__)

@pytest.fixture
def certificate_chain_service():
    return CertificateChainService()

@pytest.fixture
def self_signed_cert():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    return cert

@pytest.fixture
def rsa_cert_chain():
    # Generate root CA private key
    root_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create root CA certificate
    root_subject = root_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"root-ca.com"),
    ])
    
    root_cert = x509.CertificateBuilder().subject_name(
        root_subject
    ).issuer_name(
        root_issuer
    ).public_key(
        root_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(root_private_key, hashes.SHA256())
    
    # Generate intermediate CA private key
    intermediate_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create intermediate CA certificate
    intermediate_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"intermediate-ca.com"),
    ])
    
    intermediate_cert = x509.CertificateBuilder().subject_name(
        intermediate_subject
    ).issuer_name(
        root_subject
    ).public_key(
        intermediate_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).sign(root_private_key, hashes.SHA256())
    
    # Generate leaf certificate private key
    leaf_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create leaf certificate
    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    
    leaf_cert = x509.CertificateBuilder().subject_name(
        leaf_subject
    ).issuer_name(
        intermediate_subject
    ).public_key(
        leaf_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(intermediate_private_key, hashes.SHA256())
    
    return [leaf_cert, intermediate_cert, root_cert]

@pytest.fixture
def ecdsa_cert_chain():
    # Generate root CA private key
    root_private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Create root CA certificate
    root_subject = root_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"root-ca.com"),
    ])
    
    root_cert = x509.CertificateBuilder().subject_name(
        root_subject
    ).issuer_name(
        root_issuer
    ).public_key(
        root_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(root_private_key, hashes.SHA256())
    
    # Generate leaf certificate private key
    leaf_private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Create leaf certificate
    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    
    leaf_cert = x509.CertificateBuilder().subject_name(
        leaf_subject
    ).issuer_name(
        root_subject
    ).public_key(
        leaf_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(root_private_key, hashes.SHA256())
    
    return [leaf_cert, root_cert]

def test_empty_certificate_chain(certificate_chain_service):
    """Test validation of empty certificate chain"""
    result = certificate_chain_service.validate_chain([])
    assert not result, "Empty certificate chain should be invalid"

def test_self_signed_certificate(certificate_chain_service, self_signed_cert):
    """Test validation of self-signed certificate"""
    result = certificate_chain_service.validate_chain([self_signed_cert])
    assert result, "Self-signed certificate should be valid"

def test_rsa_certificate_chain(certificate_chain_service, rsa_cert_chain):
    """Test validation of RSA certificate chain"""
    result = certificate_chain_service.validate_chain(rsa_cert_chain)
    assert result, "RSA certificate chain should be valid"

def test_ecdsa_certificate_chain(certificate_chain_service, ecdsa_cert_chain):
    """Test validation of ECDSA certificate chain"""
    result = certificate_chain_service.validate_chain(ecdsa_cert_chain)
    assert result, "ECDSA certificate chain should be valid"

def test_invalid_certificate_chain(certificate_chain_service, rsa_cert_chain):
    """Test validation of invalid certificate chain"""
    # Create an invalid chain by swapping certificates
    invalid_chain = [rsa_cert_chain[0], rsa_cert_chain[2], rsa_cert_chain[1]]
    results = certificate_chain_service.validate_chain(invalid_chain)
    # Check that all validations failed
    assert all(not result['valid'] for result in results), "Invalid certificate chain should have all validations fail"

