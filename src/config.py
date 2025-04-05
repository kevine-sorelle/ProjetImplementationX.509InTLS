# SERVER Configuration
import os

SERVER_PORT = 443
SERVER_HOST = 'google.com'

# Trusted Issuers
TRUSTED_ISSUERS = [
    'Google Trust Services',
    'GlobalSign',
    'DigiCert',
    'Let\'s Encrypt',
    'Sectigo',
    'Amazon',
    'GTS CA',
    'Google Internet Authority',
    'Cloudflare',
    'Microsoft',
    'Apple',
    'Comodo'
]

# Secret Key
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Self-Signed Certificate
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048

# Certificate Authority
CA_KEY_SIZE = 2048
CA_PUBLIC_EXPONENT = 65537
CA_SUBJECT = {
    'countryName': 'FR',
    'stateOrProvinceName': 'Paris',
    'localityName': 'Paris',
    'organizationName': 'CA',
}

# Server
SERVER_SUBJECT = {
    'countryName': 'FR',
    'stateOrProvinceName': 'Paris',
}
SERVER_LISTEN = 5
SOCKET_SERVER_PORT = 8443
SOCKET_SERVER_HOST = 'localhost'

# Certificat
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

# Define secure algorithms and their minimum key sizes
SECURE_ALGORITHMS = {
        'RSA': {
            'min_key_size': 2048,
            'secure_hashes': ['sha256', 'sha384', 'sha512']
        },
        'ECDSA': {
            'secure_curves': ['secp256r1', 'secp384r1', 'secp521r1'],
            'secure_hashes': ['sha256', 'sha384', 'sha512']
        },
        'Ed25519': {},  # Ed25519 is considered secure by default
        'Ed448': {}     # Ed448 is considered secure by default
 }

    
   
    
# Define deprecated algorithms that should be flagged
DEPRECATED_ALGORITHMS = {
        'MD5': 'MD5 is cryptographically broken',
        'SHA1': 'SHA1 is cryptographically broken',
        'RSA': {
            'min_key_size': 1024,
            'message': 'RSA keys smaller than 2048 bits are considered insecure'
        }
}