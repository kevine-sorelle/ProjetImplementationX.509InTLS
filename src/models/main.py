from wsgiref.validate import validator

from src.models.DateValidator import DateValidator
from src.models.OpenSSLParser import OpenSSLParser
from src.models.SSLCertificateFetcher import SSLCertificateFetcher
from src.models.SSLConnectionManager import SSLConnectionManager
from src.models.analyseCertificate import AnalyseCertificate
from src.models.certificateMetadata import CertificateMetadata
from src.models.getCertificate import GetCertificate

#----------------------------------------- Exemple d'usage ------------------------
if __name__ == "__main__":
    connection = SSLConnectionManager("google.com", 443)
    fetcher = SSLCertificateFetcher()
    cert_retriever = GetCertificate(connection, fetcher)
    print(f"this is the hostname {connection.hostname}")
    print(f"this is the port {connection.port}")
    #print(f"this is the fetcher {fetcher.fetchCertificate()}")

    pem_cert = cert_retriever.getCertificate()
    print(pem_cert)

    # Créer une implémentation concrète pour l'analyse d'un certificat
    parser = OpenSSLParser()
    validator = DateValidator()
    meta = CertificateMetadata()

    """Création de l'objet qui permet d'effectuer 
    l'analyse d'un certificat avec ses dépendances"""
    analyser = AnalyseCertificate(parser, validator, meta)

    """Exemple de certificat PEM"""
    pem_certificate = """
    -----BEGIN CERTIFICATE-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END CERTIFICATE-----
    """

    # Analyse du certificat
    result = analyser.analyseCertificate(pem_cert)
    print(f"Les résultats de l'analyse du certificat {result}")

