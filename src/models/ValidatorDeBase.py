from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append("src")
from models.getCertificate import GetCertificate
from models.validatorInterface import ValidatorInterface

"""Implémentation de la classe ValidatorDeBase(Component)"""
class ValidatorDeBase(ValidatorInterface):


    def validate(self,certificate):
        cert = None
        if isinstance(certificate, str):
            cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        return cert