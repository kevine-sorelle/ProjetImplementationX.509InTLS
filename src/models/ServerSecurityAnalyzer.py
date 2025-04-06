from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import socket
import ssl
import sys
sys.path.append("src")
from models.certificat import Certificat
from models.ValidationStrategy import ValidationStrategy
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

class ServerSecurityAnalyzer:
    """
    Analyzes server security parameters and certificate information.
    Replaces the KEM and KeyGenerator classes with more relevant functionality.
    """
    
    def __init__(self):
        """Initialize the ServerSecurityAnalyzer"""
        # Initialize with all available validator types
        validator_types = ['algorithm', 'date', 'key', 'signature', 'subject']
        self.validation_strategy = ValidationStrategy(validator_types)
    
    def analyze_server(self, hostname, port=443):
        """
        Analyze a server's security parameters and certificates.
        
        Args:
            hostname: The hostname to analyze
            port: The port to connect to (default: 443 for HTTPS)
            
        Returns:
            dict: Server security information
        """
        try:
            # Get IP address
            ip_address = socket.gethostbyname(hostname)
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert_bytes = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                    
                    # Get cipher information
                    cipher = ssock.cipher()
                    
                    # Get protocol version
                    protocol_version = ssock.version()
                    
                    # Check for OCSP stapling
                    ocsp_stapling = self._check_ocsp_stapling(ssock)
                    
                    # Create Certificat object
                    cert_obj = Certificat(x509_cert=x509_cert)
                    
                    # Validate certificate
                    validation_results = self.validation_strategy.validate_certificate(cert_obj)
                    
                    # Count valid and invalid certificates
                    logger.debug("[DEBUG] validation_results =", validation_results)
                    logger.debug("[DEBUG] result types =", [type(r) for r in validation_results.values()])
                    valid_certificates = 1 if all(result.get('valid', False) for result in validation_results.values()) else 0
                    invalid_certificates = 1 if not all(result.get('valid', False) for result in validation_results.values()) else 0
                    
                    # Extract certificate information
                    logger.debug("[DEBUG] Running _extract_certificate_info")
                    cert_info = self._extract_certificate_info(cert_obj)
                    
                    # Generate security recommendations
                    security_recommendations = self._generate_security_recommendations(
                        cert_info, validation_results, protocol_version, cipher
                    )
                    
                    # Compile all information
                    server_info = {
                        'hostname': hostname,
                        'port': port,
                        'ip_address': ip_address,
                        'total_certificates': 1,
                        'valid_certificates': valid_certificates,
                        'invalid_certificates': invalid_certificates,
                        'subject_cn': cert_info.get('subject_cn', 'Unknown'),
                        'subject_o': cert_info.get('subject_o', 'Unknown'),
                        'subject_c': cert_info.get('subject_c', 'Unknown'),
                        'not_before': cert_info.get('not_before', 'Unknown'),
                        'not_after': cert_info.get('not_after', 'Unknown'),
                        'days_remaining': cert_info.get('days_remaining', 0),
                        'key_type': cert_info.get('key_type', 'Unknown'),
                        'key_size': cert_info.get('key_size', 0),
                        'signature_algorithm': cert_info.get('signature_algorithm', 'Unknown'),
                        'tls_version': protocol_version,
                        'cipher_suites': [cipher[0]] if cipher else [],
                        'ocsp_stapling': ocsp_stapling
                    }
                    
                    return {
                        'server_info': server_info,
                        'validation_results': validation_results,
                        'security_recommendations': security_recommendations
                    }
                    
        except Exception as e:
            return {
                'error': str(e),
                'server_info': None,
                'validation_results': {},
                'security_recommendations': []
            }
    
    def _get_certificate_chain(self, hostname, port):
        """
        Get the complete certificate chain for a server.
        
        Args:
            hostname: The hostname to get certificates for
            port: The port to connect to
            
        Returns:
            list: List of certificates in the chain
        """
        try:
            # Use ssl to get the certificate
            cert = ssl.get_server_certificate((hostname, port))
            cert_obj = x509.load_pem_x509_certificate(cert.encode())
            
            # For simplicity, we'll just return the leaf certificate
            # In a real implementation, you would fetch the full chain
            return [cert_obj]
        except Exception:
            return []
    
    def _validate_certificates(self, cert_chain):
        """
        Validate all certificates in the chain.
        
        Args:
            cert_chain: List of certificates to validate
            
        Returns:
            dict: Validation results for each certificate
        """
        results = {}
        
        for i, cert in enumerate(cert_chain):
            # Create a Certificat object
            cert_obj = Certificat()
            cert_obj.cert = cert
            
            # Validate the certificate
            validation_results = self.validation_strategy.validate_certificate(cert_obj)
            
            # Store results
            results[f'certificate_{i+1}'] = validation_results
            
        return results
    
    def _extract_certificate_info(self, cert):
        """
        Extract useful information from a certificate.
        
        Args:
            cert: The certificate to extract information from
            
        Returns:
            dict: Certificate information
        """
        logger.debug("[DEBUG] Running _extract_certificate_info")

        # if cert is a string, convert it to a certificate object
        logger.debug("[DEBUG] Cert type:", type(cert))
        if isinstance(cert, str):
            logger.debug("[DEBUG] Received a string cert, attempting to parse...")
            cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            logger.debug("[DEBUG] Parsed cert type:", type(cert))

        info = {}
        
        try:
            # Create Certificat object if needed
            if not isinstance(cert, Certificat):
                cert_obj = Certificat(x509_cert=cert)
            else:
                cert_obj = cert

            # Extract subject information
            subject = cert_obj.x509_cert.subject
            for attr in subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    info['subject_cn'] = attr.value
                elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                    info['subject_o'] = attr.value
                elif attr.oid == x509.NameOID.COUNTRY_NAME:
                    info['subject_c'] = attr.value
            
            # Extract validity period
            info['not_before'] = cert_obj.x509_cert.not_valid_before.strftime('%Y-%m-%d')
            info['not_after'] = cert_obj.x509_cert.not_valid_after.strftime('%Y-%m-%d')
            
            # Calculate days remaining
            now = datetime.now()
            days_remaining = (cert_obj.x509_cert.not_valid_after - now).days
            info['days_remaining'] = max(0, days_remaining)
            
            # Extract key information
            public_key = cert_obj.get_public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                info['key_type'] = 'RSA'
                info['key_size'] = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                info['key_type'] = 'ECDSA'
                info['key_size'] = public_key.curve.key_size
            else:
                info['key_type'] = 'Unknown'
                info['key_size'] = 0
            
            # Extract signature algorithm
            try:
                sig_algorithm = cert_obj.get_signature_algorithm()
                if hasattr(sig_algorithm, 'name'):
                    info['signature_algorithm'] = sig_algorithm.name
                else:
                    info['signature_algorithm'] = str(sig_algorithm)
            except AttributeError:
                info['signature_algorithm'] = 'Unknown'
            
        except Exception as e:
            logger.error(f"Error extracting certificate info: {str(e)}")
            # Set default values if extraction fails
            info.setdefault('subject_cn', 'Unknown')
            info.setdefault('subject_o', 'Unknown')
            info.setdefault('subject_c', 'Unknown')
            info.setdefault('not_before', 'Unknown')
            info.setdefault('not_after', 'Unknown')
            info.setdefault('days_remaining', 0)
            info.setdefault('key_type', 'Unknown')
            info.setdefault('key_size', 0)
            info.setdefault('signature_algorithm', 'Unknown')
            
        return info
    
    def _check_ocsp_stapling(self, ssock):
        """
        Check if OCSP stapling is supported.
        
        Args:
            ssock: The SSL socket
            
        Returns:
            bool: True if OCSP stapling is supported, False otherwise
        """
        # This is a simplified check
        # In a real implementation, you would check for the OCSP response
        try:
            # Try to get OCSP response
            ocsp_response = ssock.get_ocsp_response()
            return ocsp_response is not None
        except:
            return False
    
    def _generate_security_recommendations(self, cert_info, validation_results, protocol_version, cipher):
        """
        Generate security recommendations based on the analysis.
        
        Args:
            cert_info: Certificate information
            validation_results: Validation results
            protocol_version: TLS protocol version
            cipher: Cipher information
            
        Returns:
            list: List of security recommendations
        """
        recommendations = []
        
        # Check certificate expiration
        days_remaining = cert_info.get('days_remaining', 0)
        if days_remaining < 30:
            recommendations.append({
                'title': 'Certificate Expiring Soon',
                'description': f'The certificate will expire in {days_remaining} days. Renew it immediately.',
                'severity': 'high'
            })
        elif days_remaining < 90:
            recommendations.append({
                'title': 'Certificate Expiring Soon',
                'description': f'The certificate will expire in {days_remaining} days. Plan to renew it soon.',
                'severity': 'medium'
            })
        
        # Check key size
        key_size = cert_info.get('key_size', 0)
        key_type = cert_info.get('key_type', '')
        
        if key_type == 'RSA' and key_size < 2048:
            recommendations.append({
                'title': 'Weak RSA Key Size',
                'description': f'RSA key size of {key_size} bits is below the recommended minimum of 2048 bits.',
                'severity': 'high'
            })
        elif key_type == 'ECDSA' and key_size < 256:
            recommendations.append({
                'title': 'Weak ECDSA Key Size',
                'description': f'ECDSA key size of {key_size} bits is below the recommended minimum of 256 bits.',
                'severity': 'high'
            })
        
        # Check TLS version
        if protocol_version < 'TLSv1.2':
            recommendations.append({
                'title': 'Outdated TLS Version',
                'description': f'TLS version {protocol_version} is outdated. Upgrade to TLS 1.2 or higher.',
                'severity': 'high'
            })
        
        # Check for validation failures
        for test_name, result in validation_results.items():
            if not result.get('valid', False):
                recommendations.append({
                    'title': f'Failed {test_name} Validation',
                    'description': result.get('message', 'Validation failed'),
                    'severity': 'high'
                })
        
        # Check cipher strength
        if cipher:
            cipher_name = cipher[0]
            if 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
                recommendations.append({
                    'title': 'Weak Cipher Suite',
                    'description': f'Cipher suite {cipher_name} is considered weak. Use stronger ciphers.',
                    'severity': 'high'
                })
        
        return recommendations

    def analyze_server_with_cert(self, certificate, hostname, port=443):
        """
        Analyze a server's security parameters using an existing certificate.
        
        Args:
            certificate: The existing certificate object
            hostname: The hostname to analyze
            port: The port to connect to (default: 443 for HTTPS)
            
        Returns:
            dict: Server security information
        """
        try:
            # Ensure certificate is a x509.Certificate object
            if isinstance(certificate, str):
                logger.debug("[DEBUG] Converting PEM string to x509 object")
                x509_cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
            elif isinstance(certificate, bytes):
                logger.debug("[DEBUG] Converting bytes to x509 object")
                x509_cert = x509.load_der_x509_certificate(certificate, default_backend())
            elif isinstance(certificate, x509.Certificate):
                x509_cert = certificate
            elif isinstance(certificate, Certificat):
                x509_cert = certificate.x509_cert
            else:
                raise TypeError(f"Unsupported certificate type: {type(certificate)}")

            # Create Certificat object
            cert_obj = Certificat(x509_cert=x509_cert)

            # Get IP address
            ip_address = socket.gethostbyname(hostname)
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to server to get TLS information
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get cipher information
                    cipher = ssock.cipher()
                    
                    # Get protocol version
                    protocol_version = ssock.version()
                    
                    # Check for OCSP stapling
                    ocsp_stapling = self._check_ocsp_stapling(ssock)
            
            # Validate certificates
            validation_results = self.validation_strategy.validate_certificate(cert_obj)
            
            # Count valid and invalid certificates
            valid_certificates = 1 if all(result.get('valid', False) for result in validation_results.values()) else 0
            invalid_certificates = 1 if not all(result.get('valid', False) for result in validation_results.values()) else 0
            
            # Extract certificate information
            logger.debug("[DEBUG] Running _extract_certificate_info")
            cert_info = self._extract_certificate_info(cert_obj)
            
            # Generate security recommendations
            security_recommendations = self._generate_security_recommendations(
                cert_info, validation_results, protocol_version, cipher
            )
            
            # Compile all information
            server_info = {
                'hostname': hostname,
                'port': port,
                'ip_address': ip_address,
                'total_certificates': 1,
                'valid_certificates': valid_certificates,
                'invalid_certificates': invalid_certificates,
                'subject_cn': cert_info.get('subject_cn', 'Unknown'),
                'subject_o': cert_info.get('subject_o', 'Unknown'),
                'subject_c': cert_info.get('subject_c', 'Unknown'),
                'not_before': cert_info.get('not_before', 'Unknown'),
                'not_after': cert_info.get('not_after', 'Unknown'),
                'days_remaining': cert_info.get('days_remaining', 0),
                'key_type': cert_info.get('key_type', 'Unknown'),
                'key_size': cert_info.get('key_size', 0),
                'signature_algorithm': cert_info.get('signature_algorithm', 'Unknown'),
                'tls_version': protocol_version,
                'cipher_suites': [cipher[0]] if cipher else [],
                'ocsp_stapling': ocsp_stapling
            }
            
            return {
                'server_info': server_info,
                'validation_results': validation_results,
                'security_recommendations': security_recommendations
            }
                
        except Exception as e:
            return {
                'error': str(e),
                'server_info': None,
                'validation_results': {},
                'security_recommendations': []
            } 