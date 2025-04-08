from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template, send_file, session, redirect, url_for, flash
import sys
sys.path.append("src")
from models.certificat import Certificat
from models.validatorInterface import ValidatorInterface
from facade.ServerSecurityFacade import ServerSecurityFacade
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import SECRET_KEY
from services.SecurityTest import SecurityTest
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate
import os

from models.ValidatorFactory import ValidatorFactory
from models.ValidationStrategy import ValidationStrategy
from factrory.SecurityAnalyzerFactory import SecurityAnalyzerFactory
from strategy.CertificateBasedAnalyzer import CertificateBasedAnalyzer
from strategy.StandardSecurityAnalyzer import StandardSecurityAnalyzer
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'

# Register analyzers
SecurityAnalyzerFactory.register_analyzer("standard", StandardSecurityAnalyzer)
SecurityAnalyzerFactory.register_analyzer("certificate", CertificateBasedAnalyzer)

# Initialize the server security analyzer
security_facade = ServerSecurityFacade()

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
            
            # Log certificate details before storing in session
            logger.debug(f"Certificate type before session storage: {type(certificate)}")
            logger.debug(f"Certificate value: {certificate[:100]}..." if isinstance(certificate, str) else "Non-string certificate")
            
            # Store in session for other routes
            session["certificate"] = certificate
            session["hostname"] = hostname
            session["port"] = port
            
            # Verify session storage
            logger.debug(f"Session after storage: certificate={bool(session.get('certificate'))}, "
                        f"hostname={session.get('hostname')}, port={session.get('port')}")
            
            # Create validation strategy with selected validators
            strategy = ValidationStrategy(selected_validators)
            validation_results = strategy.validate_certificate(certificate)
            
            return render_template('pages/index.html',
                                hostname=hostname,
                                validation_results=validation_results,
                                available_validators=ValidatorFactory.get_available_validators())
        except Exception as e:
            logger.error(f"Error in index route: {str(e)}", exc_info=True)
            flash(str(e), "error")
            return render_template('pages/index.html',
                                hostname=hostname,
                                validation_results={'error': {'valid': False, 'message': str(e)}},
                                available_validators=ValidatorFactory.get_available_validators())
    
    return render_template('pages/index.html',
                         available_validators=ValidatorFactory.get_available_validators())

@app.route("/server-security", methods=["GET", "POST"])
def server_security():
    """Server security dashboard showing detailed security information"""
    logger.debug("Entering server_security route")
    logger.debug(f"Session data: certificate present={bool(session.get('certificate'))}, "
                f"hostname={session.get('hostname')}, port={session.get('port')}")
    
    if request.method == "POST":
        hostname = request.form.get('hostname')
        port = int(request.form.get('port', 443))
        
        try:
            logger.debug(f"Analyzing server: {hostname}:{port}")
            analysis_results = security_facade.analyze_server(hostname, port)
            
            if analysis_results.get('error'):
                logger.error(f"Error from security facade: {analysis_results['error']}")
                flash(analysis_results['error'], "error")
                return render_template('pages/server_security_dashboard.html')
            
            logger.debug("Analysis successful, rendering template with results")
            return render_template('pages/server_security_dashboard.html',
                                server_info=analysis_results.get('server_info', {}),
                                validation_results=analysis_results.get('validation_results', {}),
                                security_recommendations=analysis_results.get('security_recommendations', []))
        except Exception as e:
            logger.error(f"Error analyzing server: {str(e)}", exc_info=True)
            flash(str(e), "error")
            return render_template('pages/server_security_dashboard.html')
    
    # For GET requests, check if we have a certificate in session
    certificate = session.get("certificate")
    hostname = session.get("hostname")
    port = session.get("port", 443)
    
    logger.debug(f"GET request - Certificate type: {type(certificate)}")
    logger.debug(f"GET request - Hostname: {hostname}, Port: {port}")
    
    if certificate and hostname:
        try:
            # Convert certificate if it's a string
            if isinstance(certificate, str):
                logger.debug("Converting PEM string to certificate object")
                x509_cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

                # Reset the singleton before creating a new instance
                Certificat.reset()
                cert_obj = Certificat(x509_cert=x509_cert)

                logger.debug(f"Certificate object created successfully: {cert_obj}")
            else:
                cert_obj = certificate
            logger.debug(f"Certificate object type after conversion: {type(cert_obj)}")
            logger.debug("Analyzing server with certificate")
            analysis_results = security_facade.analyze_server(hostname, port, cert_obj)
            
            if analysis_results.get('error'):
                logger.error(f"Error from security facade: {analysis_results['error']}")
                flash(analysis_results['error'], "error")
                return render_template('pages/server_security_dashboard.html')
            
            logger.debug("Analysis successful, rendering template with results")
            return render_template('pages/server_security_dashboard.html',
                                server_info=analysis_results.get('server_info', {}),
                                validation_results=analysis_results.get('validation_results', {}),
                                security_recommendations=analysis_results.get('security_recommendations', []))
        except Exception as e:
            logger.error(f"Error processing certificate from session: {str(e)}", exc_info=True)
            flash(str(e), "error")
    else:
        logger.warning("No certificate or hostname in session")
        flash("No server information available. Please validate a certificate first.", "warning")
    
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