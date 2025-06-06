from cryptography.hazmat.primitives import serialization
from flask import Flask, request, render_template, send_file, session, redirect, url_for, flash
import sys
sys.path.append("src")
from models.KEM import KEM
from models.certificat import Certificat
from models.validatorInterface import ValidatorInterface
from facade.ServerSecurityFacade import ServerSecurityFacade
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config.config import SECRET_KEY
from services.SecurityTest import SecurityTest
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate
import os

from models.ValidatorFactory import ValidatorFactory
from models.ValidationStrategy import ValidationStrategy
from factory.SecurityAnalyzerFactory import SecurityAnalyzerFactory
from strategy.CertificateBasedAnalyzer import CertificateBasedAnalyzer
from strategy.StandardSecurityAnalyzer import StandardSecurityAnalyzer
from utils.logger_config import setup_logger
from models.keyGenerator import KeyGenerator
from factory.CertificateFactory import CertificateFactory
from adaptator.CertificateAdapterFactory import CertificateAdapterFactory

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
        validation_type = request.form.get('validation_type', 'hostname')
        selected_validators = request.form.getlist('validators')
        
        try:
            if validation_type == 'hostname':
                hostname = request.form.get('hostname')
                port = int(request.form.get('port', 443))
                
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
                
            else:  # file validation
                if 'certificate_file' not in request.files:
                    flash("No certificate file provided", "error")
                    return render_template('pages/index.html',
                                        available_validators=ValidatorFactory.get_available_validators())
                
                certificate_file = request.files['certificate_file']
                if certificate_file.filename == '':
                    flash("No selected file", "error")
                    return render_template('pages/index.html',
                                        available_validators=ValidatorFactory.get_available_validators())
                
                # Read the certificate file
                certificate = certificate_file.read().decode('utf-8')
                
                # Store in session for other routes
                session["certificate"] = certificate
                session["hostname"] = "file_upload"
                session["port"] = None
            
            # Create validation strategy with selected validators
            strategy = ValidationStrategy(selected_validators)
            validation_results = strategy.validate_certificate(certificate)
            
            return render_template('pages/index.html',
                                hostname=session.get("hostname"),
                                port=session.get("port"),
                                validation_results=validation_results,
                                available_validators=ValidatorFactory.get_available_validators())
            
        except Exception as e:
            logger.error(f"Error in index route: {str(e)}", exc_info=True)
            flash(str(e), "error")
            return render_template('pages/index.html',
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

@app.route("/generator", methods=["GET", "POST"])
def generator():
    if request.method == 'POST':
        try:
            # Get form data with correct field names
            subject = request.form.get('subject')
            organization = request.form.get('organization')
            country = request.form.get('country')
            validity_days = int(request.form.get('validity_days', 365))
            key_type = request.form.get('key_type', 'EC')
            key_size = int(request.form.get('key_size', 256))
            hash_algorithm = request.form.get('hash_algorithm', 'SHA256')
            include_kem = request.form.get('include_kem') == 'on'

            # Validate required fields
            if not all([subject, organization, country]):
                flash("Tous les champs obligatoires doivent être remplis", "error")
                return render_template('pages/generator.html')

            # Create certificate factory
            factory = CertificateFactory()
            
            # Generate certificate with selected parameters
            cert = factory.create_certificate(
                subject=subject,
                organization=organization,
                country=country,
                validity_days=validity_days,
                key_type=key_type,
                key_size=key_size,
                hash_algorithm=hash_algorithm,
                include_kem=include_kem
            )

            # Store certificate and info in session for display and download
            session['generated_certificate'] = cert['certificate']
            session['generated_cert_info'] = {
                'subject': subject,
                'organization': organization,
                'country': country,
                'validity_days': validity_days,
                'key_type': key_type,
                'key_size': key_size,
                'hash_algorithm': hash_algorithm,
                'include_kem': include_kem
            }

            flash('Certificat généré avec succès!', 'success')
            return render_template('pages/generator.html',
                                cert_pem=session['generated_certificate'],
                                subject=subject,
                                organization=organization,
                                country=country,
                                validity_days=validity_days,
                                key_size=key_size,
                                include_kem=include_kem)

        except ValueError as e:
            flash(f"Erreur de validation: {str(e)}", "error")
        except Exception as e:
            flash(f"Erreur lors de la génération du certificat: {str(e)}", "error")
            logger.error(f"Error generating certificate: {str(e)}", exc_info=True)

    return render_template('pages/generator.html')

@app.route("/download", methods=["GET"])
def download():
    """Permettre aux utilisateurs de télécharger le certificat stocké en session."""
    # Get the certificate and related data from the session
    cert = session.get("certificate", None)
    hostname = session.get("hostname", "Unknown")
    port = session.get("port", 443)
    
    if not cert:
        flash("Aucun certificat n'est disponible pour le téléchargement. Veuillez d'abord valider un certificat ou analyser la sécurité d'un serveur.", "warning")
        return render_template("pages/download.html", certificate=None)
    
    try:
        # Create a temporary file to store the certificate
        temp_path = os.path.join(os.path.dirname(__file__), "temp_cert.pem")
        with open(temp_path, "w") as f:
            f.write(cert)
        
        # Generate a meaningful filename
        filename = f"certificate_{hostname}_{port}.pem"
        
        # Send the file
        return send_file(
            temp_path, 
            as_attachment=True, 
            download_name=filename,
            mimetype="application/x-pem-file"
        )
    except Exception as e:
        logger.error(f"Error in download route: {str(e)}", exc_info=True)
        flash(f"Erreur lors du téléchargement du certificat: {str(e)}", "error")
        return render_template("pages/download.html", 
                              certificate=cert, 
                              hostname=hostname, 
                              port=port)

@app.route("/download-generated", methods=["GET"])
def download_generated():
    """Permettre aux utilisateurs de télécharger le certificat généré."""
    # Get the generated certificate and related data from the session
    cert = session.get("generated_certificate", None)
    cert_info = session.get("generated_cert_info", {})
    
    if not cert:
        flash("Aucun certificat généré n'est disponible pour le téléchargement. Veuillez d'abord générer un certificat.", "warning")
        return redirect(url_for('generator'))
    
    try:
        # Create a temporary file to store the certificate
        temp_path = os.path.join(os.path.dirname(__file__), "temp_generated_cert.pem")
        with open(temp_path, "w") as f:
            f.write(cert)
        
        # Generate a meaningful filename
        filename = f"generated_certificate_{cert_info.get('subject', 'unknown')}.pem"
        
        # Send the file
        return send_file(
            temp_path, 
            as_attachment=True, 
            download_name=filename,
            mimetype="application/x-pem-file"
        )
    except Exception as e:
        logger.error(f"Error in download_generated route: {str(e)}", exc_info=True)
        flash(f"Erreur lors du téléchargement du certificat généré: {str(e)}", "error")
        return redirect(url_for('generator'))

if __name__ == "__main__":
    app.run(debug=True)