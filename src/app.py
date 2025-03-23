from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template, send_file
import sys
sys.path.append("src")
from models.validatorInterface import ValidatorInterface



from models.KEM import KEM
from models.certificateManager import CertificateManager
from models.keyGenerator import KeyGenerator
from models.DateValidator import DateValidator
from models.OpenSSLParser import OpenSSLParser
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.certificateMetadata import CertificateMetadata
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate
import os

app = Flask(__name__)

# Initialisation des classes maitresses
key_gen = KeyGenerator()
cert_manager = CertificateManager(key_gen)
kem = KEM()

# Generation du certificat X.509
CERT_PATH = os.path.join(os.path.dirname(__file__), "kem_cert.pem")
if not os.path.exists(CERT_PATH):
    cert_manager.createSelfSignedCert("kem-test.local", CERT_PATH)


@app.route("/", methods=["GET", "POST"])
def home():
    cert_info = {}
    try:
        if request.method == "POST":
                hostname = request.form["hostname"]
                port = request.form["port"]
                connection = SSLConnectionManager(hostname, port)
                fetcher = SSLCertificateFetcher()
                certificate_retriever = GetCertificate(connection, fetcher)
                analyser = AnalyseCertificate()
                my_certificate = certificate_retriever.getCertificate()
                data = analyser.analyseCertificate(my_certificate)
                cert_info = {"hostname": hostname, "valid": data["is_valid"], "issuer": data["issuer"], "subject": data["subject"]}
        else:
            cert_info = {}
    except Exception as e:
        # ajout de l'information d'erreur pour cert_info
        cert_info["Invalid"] = f"Erreur: {str(e)}"
    return render_template("pages/index.html", cert_info=cert_info)

@app.route("/generator")
def generator():
    """Genration et affichage des details du certificat et chiffrement KEM"""
    cert = cert_manager.loadCertificate(cert_path=CERT_PATH)
    pub_key = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    enc_key = kem.encapsulate()
    dec_key = kem.decapsulate(enc_key)
    return render_template("pages/generator.html",
                           cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
                           public_key=pub_key,
                           enc_key=enc_key.hex(),
                           dec_key=dec_key.hex())

@app.route("/download")
def download():
    """Permettre aux utilisateurs de télécharger le certificat généré."""
    return send_file(CERT_PATH, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)