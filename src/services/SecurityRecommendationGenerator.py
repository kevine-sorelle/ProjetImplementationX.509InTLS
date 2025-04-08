from typing import Dict, List
from utils.logger_config import setup_logger
from datetime import datetime

# Set up logger for this module
logger = setup_logger(__name__)


class SecurityRecommendationGenerator:
    @staticmethod
    def generate_recommendations(cert_info: Dict, validation_results: Dict, protocol_version: str, cipher: tuple) -> List:
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
        logger.debug(f"Certificate expiration: {days_remaining} days remaining")

        # If days_remaining is 0 but we have date strings, calculate it manually
        if days_remaining == 0 and 'not_after' in cert_info and cert_info['not_after'] != 'Unknown': 
            try:
                # Parse the date string (assuming format YYYY-MM-DD)
                not_after_date = datetime.strptime(cert_info['not_after'], '%Y-%m-%d')
                today = datetime.now()
                days_remaining = (not_after_date - today).days
                logger.debug(f"Calculated days remaining: {days_remaining} days from {cert_info['not_after']}")
            except ValueError:
                logger.error(f"Error parsing date string: {cert_info['not_after']}")
                days_remaining = 0
        logger.debug(f"Final days remaining: {days_remaining} days")
        logger.debug(f"type of this {type(days_remaining)}")
        logger.debug(f"type of this {type(cert_info['days_remaining'])}")
        logger.debug(f"type of this {days_remaining - 30}")
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
        if protocol_version and protocol_version < 'TLSv1.2':
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


