import pytest
from cryptography import x509

def test_certificate_chain():
    # Load the certificate and issuer
    with open("tests/certs/google_cert_chain.pem", "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    with open("tests/certs/google_cert_root.pem", "rb") as issuer_file:
        issuer = x509.load_pem_x509_certificate(issuer_file.read())
    
    # Print certificate details for debugging
    print("\nCertificate Details:")
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Signature Algorithm: {cert.signature_algorithm_oid}")
    print(f"Not Valid Before: {cert.not_valid_before}")
    print(f"Not Valid After: {cert.not_valid_after}")
    
    print("\nIssuer Certificate Details:")
    print(f"Subject: {issuer.subject}")
    print(f"Issuer: {issuer.issuer}")
    print(f"Signature Algorithm: {issuer.signature_algorithm_oid}")
    
    # Verify the chain
    assert cert.issuer == issuer.subject, "Certificate chain is not valid"
    print("\nCertificate chain is valid!") 