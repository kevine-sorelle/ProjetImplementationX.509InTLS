import sys
sys.path.append("src")
from models.ValidatorDeBase import ValidatorDeBase
from models.DateValidator import DateValidator
from models.IssuerValidator import IssuerValidator
from models.OpenSSLParser import OpenSSLParser
from models.Validator import Validator



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

    def __init__(self):
        self.validator_simple = ValidatorDeBase()
        self.validator_date = DateValidator(ValidatorDeBase())
        self.validator_d = Validator(validator=self.validator_date)
        self.validator_issuer = IssuerValidator(ValidatorDeBase())
        self.validator_i = Validator(validator=self.validator_issuer)
        self.parser = OpenSSLParser()


    def analyseCertificate(self, cert_pem: str) -> dict:
        cert = self.parser.parse(cert_pem)

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": self.validator_i.validate(cert),
            "validity_period": self.validator_d.validate(cert),
            "is_valid": self.validator_d.validate(cert)
        }
