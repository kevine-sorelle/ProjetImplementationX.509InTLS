# SERVER Configuration
import os

SERVER_PORT = 443
SERVER_HOST = 'google.com'

# Trusted Issuers
TRUSTED_ISSUERS = ['Google Trust Services']

# Secret Key
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))