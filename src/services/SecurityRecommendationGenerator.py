from typing import Dict, List
from utils.logger_config import setup_logger
from datetime import datetime

# Set up logger for this module
logger = setup_logger(__name__)


class SecurityRecommendationGenerator:
    def __init__(self):
        self.min_key_size = {
            'RSA': 2048,
            'EC': 256,
            'DSA': 2048
        }
        self.recommended_signature_algorithms = [
            'sha256WithRSAEncryption',
            'sha384WithRSAEncryption',
            'sha512WithRSAEncryption',
            'ecdsa-with-SHA256',
            'ecdsa-with-SHA384',
            'ecdsa-with-SHA512'
        ]
        self.recommended_protocols = ['TLSv1.2', 'TLSv1.3']

    def generate_recommendations(self, server_info: Dict, cert_info: Dict, 
                               chain_valid: bool, ocsp_status: Dict) -> List[Dict]:
        """
        Generate security recommendations based on the analysis results.
        
        Args:
            server_info: Dictionary containing server information
            cert_info: Dictionary containing certificate information
            chain_valid: Boolean indicating if the certificate chain is valid
            ocsp_status: Dictionary containing OCSP status information
            
        Returns:
            List of recommendations, each containing severity and description
        """
        recommendations = []
        
        # Check certificate chain validity
        if not chain_valid:
            recommendations.append({
                'severity': 'HIGH',
                'category': 'Certificate Chain',
                'description': 'Certificate chain validation failed. Ensure all intermediate certificates are properly installed.'
            })

        # Check OCSP status
        self._check_ocsp_status(ocsp_status, recommendations)
        
        # Check certificate validity period
        self._check_validity_period(cert_info, recommendations)
        
        # Check key strength
        self._check_key_strength(cert_info, recommendations)
        
        # Check signature algorithm
        self._check_signature_algorithm(cert_info, recommendations)
        
        # Check TLS protocol versions
        self._check_protocol_versions(server_info, recommendations)
        
        # Check cipher suites
        self._check_cipher_suites(server_info, recommendations)

        return recommendations

    def _check_ocsp_status(self, ocsp_status: Dict, recommendations: List[Dict]):
        """Check OCSP status and generate recommendations."""
        if not ocsp_status.get('available'):
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'OCSP',
                'description': 'OCSP status checking is not available. Consider enabling OCSP stapling.'
            })
        elif not ocsp_status.get('valid'):
            recommendations.append({
                'severity': 'HIGH',
                'category': 'OCSP',
                'description': 'Certificate has been revoked or is invalid according to OCSP.'
            })

    def _check_validity_period(self, cert_info: Dict, recommendations: List[Dict]):
        """Check certificate validity period and generate recommendations."""
        try:
            not_after = cert_info.get('not_after')
            if not not_after or not_after == 'Unknown':
                recommendations.append({
                    'severity': 'MEDIUM',
                    'category': 'Validity',
                    'description': 'Could not determine certificate expiration date.'
                })
                return

            # Parse the date string (format: YYYY-MM-DD)
            not_after_date = datetime.strptime(not_after, '%Y-%m-%d')
            days_until_expiry = (not_after_date - datetime.now()).days
            
            if days_until_expiry < 0:
                recommendations.append({
                    'severity': 'CRITICAL',
                    'category': 'Validity',
                    'description': 'Certificate has expired.'
                })
            elif days_until_expiry < 30:
                recommendations.append({
                    'severity': 'HIGH',
                    'category': 'Validity',
                    'description': f'Certificate will expire in {days_until_expiry} days.'
                })
            elif days_until_expiry < 90:
                recommendations.append({
                    'severity': 'MEDIUM',
                    'category': 'Validity',
                    'description': f'Certificate will expire in {days_until_expiry} days.'
                })
        except ValueError as e:
            logger.error(f"Error parsing validity period: {str(e)}")
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'Validity',
                'description': 'Could not parse certificate expiration date.'
            })
        except Exception as e:
            logger.error(f"Error checking validity period: {str(e)}")
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'Validity',
                'description': 'Error checking certificate validity period.'
            })

    def _check_key_strength(self, cert_info: Dict, recommendations: List[Dict]):
        """Check public key strength and generate recommendations."""
        try:
            public_key = cert_info.get('public_key', {})
            key_type = public_key.get('type')
            key_size = public_key.get('key_size')
            
            if key_type in self.min_key_size:
                if key_size < self.min_key_size[key_type]:
                    recommendations.append({
                        'severity': 'HIGH',
                        'category': 'Key Strength',
                        'description': f'Key size ({key_size} bits) is below recommended minimum of {self.min_key_size[key_type]} bits for {key_type}.'
                    })
        except Exception as e:
            logger.error(f"Error checking key strength: {str(e)}")

    def _check_signature_algorithm(self, cert_info: Dict, recommendations: List[Dict]):
        """Check signature algorithm and generate recommendations."""
        sig_alg = cert_info.get('signature_algorithm', '')
        if sig_alg and sig_alg not in self.recommended_signature_algorithms:
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'Signature Algorithm',
                'description': f'Signature algorithm {sig_alg} is not among recommended algorithms.'
            })

    def _check_protocol_versions(self, server_info: Dict, recommendations: List[Dict]):
        """Check TLS protocol versions and generate recommendations."""
        protocols = server_info.get('protocols', [])
        
        # Check for outdated protocols
        outdated = [p for p in protocols if p not in self.recommended_protocols]
        if outdated:
            recommendations.append({
                'severity': 'HIGH',
                'category': 'Protocol Versions',
                'description': f'Outdated TLS protocols in use: {", ".join(outdated)}. Consider disabling them.'
            })
            
        # Check for missing modern protocols
        missing = [p for p in self.recommended_protocols if p not in protocols]
        if missing:
            recommendations.append({
                'severity': 'MEDIUM',
                'category': 'Protocol Versions',
                'description': f'Modern TLS protocols not enabled: {", ".join(missing)}. Consider enabling them.'
            })

    def _check_cipher_suites(self, server_info: Dict, recommendations: List[Dict]):
        """Check cipher suites and generate recommendations."""
        ciphers = server_info.get('cipher_suites', [])
        weak_ciphers = [c for c in ciphers if 'NULL' in c or 'anon' in c or 'RC4' in c or 'DES' in c]
        
        if weak_ciphers:
            recommendations.append({
                'severity': 'HIGH',
                'category': 'Cipher Suites',
                'description': f'Weak cipher suites detected: {", ".join(weak_ciphers)}. Consider disabling them.'
            })


