from abc import ABC, abstractmethod
from cryptography import x509
import ssl
import socket
import sys
sys.path.append("src")
from models.ICertificateFetcher import ICertificateFetcher


class SSLCertificateFetcher(ICertificateFetcher):
    """Fetches x.509 certificates over SSL."""

    def fetchCertificate(self, hostname, port):
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))