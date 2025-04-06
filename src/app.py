from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template, send_file, session, redirect, url_for, flash
import sys
sys.path.append("src")
from models.validatorInterface import ValidatorInterface


from config import SECRET_KEY
from services.SecurityTest import SecurityTest
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate
import os

from models.ValidatorFactory import ValidatorFactory
from models.ValidationStrategy import ValidationStrategy
from models.ServerSecurityAnalyzer import ServerSecurityAnalyzer

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialize the server security analyzer
security_analyzer = ServerSecurityAnalyzer()

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
            session["hostname"] = hostname
            session["port"] = port
            
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

@app.route("/server-security", methods=["GET", "POST"])
def server_security():
    """Server security dashboard showing detailed security information"""
    if request.method == "POST":
        hostname = request.form.get('hostname')
        port = int(request.form.get('port', 443))
        
        try:
            # Initialize components for certificate retrieval
            ssl_manager = SSLConnectionManager(hostname, port)
            ssl_fetcher = SSLCertificateFetcher()
            cert_retriever = GetCertificate(ssl_manager, ssl_fetcher)
            
            # Get the certificate and analyze
            certificate = cert_retriever.get_certificate(hostname, port)
            analysis_results = security_analyzer.analyze_server_with_cert(certificate, hostname, port)
            
            if 'error' in analysis_results:
                flash(analysis_results['error'], "error")
                return render_template('pages/server_security_dashboard.html')
            
            return render_template('pages/server_security_dashboard.html',
                                server_info=analysis_results['server_info'],
                                validation_results=analysis_results['validation_results'],
                                security_recommendations=analysis_results['security_recommendations'])
        except Exception as e:
            flash(str(e), "error")
            return render_template('pages/server_security_dashboard.html')
    
    # For GET requests, check if we have a certificate in session
    certificate = session.get("certificate")
    hostname = session.get("hostname")
    port = session.get("port", 443)
    
    if certificate and hostname:
        try:
            analysis_results = security_analyzer.analyze_server_with_cert(certificate, hostname, port)
            return render_template('pages/server_security_dashboard.html',
                                server_info=analysis_results['server_info'],
                                validation_results=analysis_results['validation_results'],
                                security_recommendations=analysis_results['security_recommendations'])
        except Exception as e:
            flash(str(e), "error")
    
    # If no certificate or error occurred, show the default dashboard
    return render_template('pages/server_security_dashboard.html')

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
    # Get the certificate from the session
    cert = session.get("certificate", None)
    if not cert:
        return "No certificate found in session", 404
    
    # Create a temporary file to store the certificate
    temp_path = os.path.join(os.path.dirname(__file__), "temp_cert.pem")
    with open(temp_path, "w") as f:
        f.write(cert)
    
    # Send the file
    return send_file(temp_path, as_attachment=True, download_name="certificate.pem")

if __name__ == "__main__":
    app.run(debug=True)