from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template, send_file, session
import sys
sys.path.append("src")
from models.validatorInterface import ValidatorInterface


from config import SECRET_KEY
from services.SecurityTest import SecurityTest
from models.KEM import KEM
from models.certificateManager import CertificateManager
from models.keyGenerator import KeyGenerator
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate
import os

from models.ValidatorFactory import ValidatorFactory
from models.ValidationStrategy import ValidationStrategy

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialisation des classes maitresses
key_gen = KeyGenerator()
cert_manager = CertificateManager(key_gen)
kem = KEM()

# Generation du certificat X.509
CERT_PATH = os.path.join(os.path.dirname(__file__), "kem_cert.pem")
if not os.path.exists(CERT_PATH):
    cert_manager.createSelfSignedCert("kem-test.local", CERT_PATH)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        port = int(request.form.get('port', 443))
        selected_validators = request.form.getlist('validators')
        
        try:
            # Initialize components for certificate retrieval
            ssl_manager = SSLConnectionManager(hostname, port)
            ssl_fetcher = SSLCertificateFetcher()
            cert_retriever = GetCertificate(ssl_manager, ssl_fetcher)
            
            # Get the certificate
            certificate = cert_retriever.get_certificate(hostname, port)
            
            # Store in session for other routes
            session["certificate"] = certificate
            
            # Create validation strategy with selected validators
            strategy = ValidationStrategy(selected_validators)
            validation_results = strategy.validate_certificate(certificate)
            
            return render_template('pages/index.html',
                                hostname=hostname,
                                validation_results=validation_results,
                                available_validators=ValidatorFactory.get_available_validators())
        except Exception as e:
            return render_template('pages/index.html',
                                hostname=hostname,
                                validation_results={'error': {'valid': False, 'message': str(e)}},
                                available_validators=ValidatorFactory.get_available_validators())
    
    return render_template('pages/index.html',
                         available_validators=ValidatorFactory.get_available_validators())

@app.route("/generator", methods=["GET", "POST"])
def generator():
    """Generation et affichage des details du certificat et chiffrement KEM"""
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

@app.route("/tests", methods=["GET", "POST"])
def tests():
    """Page de tests"""
    test_results = {}
    try:
        # Recupération du certificat stocké dans la session
        cert = session.get("certificate", None)
        if not cert:
            raise Exception("Aucun certificat trouvé dans la sessions")
        # Exécution des tests de sécurité
        security_tests = SecurityTest()
        test_results = security_tests.securityTest(cert)
    except Exception as e:
        test_results["error"] = str(e)
    return render_template("pages/tests.html", test_results=test_results)


@app.route("/download", methods=["GET", "POST"])
def download():
    """Permettre aux utilisateurs de télécharger le certificat généré."""
    return send_file(CERT_PATH, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)