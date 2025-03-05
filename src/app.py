from flask import Flask, request, render_template
import sys
sys.path.append("src")
from models.DateValidator import DateValidator
from models.OpenSSLParser import OpenSSLParser
from models.SSLCertificateFetcher import SSLCertificateFetcher
from models.SSLConnectionManager import SSLConnectionManager
from models.certificateMetadata import CertificateMetadata
from models.getCertificate import GetCertificate
from models.analyseCertificate import AnalyseCertificate

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    cert_info = None
    try:
        if request.method == "POST":
                hostname = request.form["hostname"]
                port = request.form["port"]
                connection = SSLConnectionManager(hostname, port)
                fetcher = SSLCertificateFetcher()
                vali = DateValidator()
                parser = OpenSSLParser()
                validator = DateValidator()
                meta = CertificateMetadata()
                analyser = AnalyseCertificate(parser, validator, meta)
                get_certificate = GetCertificate(connection, fetcher)
                my_certificate = get_certificate.getCertificate()
                data = analyser.analyseCertificate(my_certificate)
                cert_info = {"hostname": hostname, "valid": data["is_valid"], "issuer": data["issuer"], "subject": data["subject"]}
        else:
            cert_info = {}
    except Exception as e:
        cert_info.pop("Invalid", f"Erreur: {str(e)}")
    return render_template("pages/index.html", cert_info=cert_info)

if __name__ == "__main__":
    app.run(debug=True)