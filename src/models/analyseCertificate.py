from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

from src.models.ICertificateMetadata import ICertificateMetadata
from src.models.ICertificateParser import ICertificateParser
from src.models.certificateValidor import ICertificateValidator
from src.models.getCertificate import GetCertificate
from src.enums.message import CertificateMessage


class AnalyseCertificate:
    """
    Classe permettant d'analyser un type certificat.

    Attributs:
    ----------
    certPem : certificat
        Il s'agit d'un certificat au format PEM.

    Objectif:
    ---------
    La classe 'AnalyseCertificate' encapsule les informations et opérations permettant d'analyser un certificat spécifique.
    """

    def __init__(self, parser: ICertificateParser, validator: ICertificateValidator, metadata: ICertificateMetadata):
        self.parser = parser
        self.validator = validator
        self.metadata = metadata

    def analyseCertificate(self, cert_pem: str) -> dict:
        cert = self.parser.parse(cert_pem)
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": self.metadata.getIssuer(cert),
            "validity_period": self.metadata.getValidityPeriod(cert),
            "is_valid": self.validator.checkCertificateValidity(cert)
        }
