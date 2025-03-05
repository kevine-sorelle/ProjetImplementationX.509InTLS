from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from abc import ABC, abstractmethod
import sys
sys.path.append("src")
from models.ICertificateParser import ICertificateParser


class OpenSSLParser(ICertificateParser):


    def parse(self, cert_pem: str) -> x509.Certificate:
        if not isinstance(cert_pem, str):
            raise ValueError("Certificate must be a PEM-formatted string")
        return x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())