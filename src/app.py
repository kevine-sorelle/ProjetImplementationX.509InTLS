from flask import Flask, request, render_template
from src.models.getCertificate import GetCertificate
from src.models.analyseCertificate import AnalyseCertificate

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    certInfo = None
    if request.method == "POST":
        hostname = request.form["hostname"]
        port = request.form["port"]
        newCertificate = GetCertificate(hostname, port)
        myCert = newCertificate.getCertificate()
        isValid, message = vali