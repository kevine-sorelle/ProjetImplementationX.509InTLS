import ssl
import socket
from cryptography import x509
from datetime import datetime

class Client:

    # creation d'un context SSL sécurisé
    def create_client(self):
        context = ssl.create_default_context()
        context.check_hostname = False

        # pour un certificat auto-signé
        context.verify_mode = ssl.CERT_NONE     # Désactivé la validation par defaut

        # connexion au serveur
        with socket.create_connection(('localhost', 8443)) as client_socket:
            with context.wrap_socket(client_socket, server_hostname='localhost') as tls_sock:
                print("Message ClientHello envoyé!")

                # Réception du certificat du serveur
                server_cert = tls_sock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(server_cert)
                print("Server certificate : ", cert.subject)
                # Echange de données
                tls_sock.send(b'Hello from the client!')
                print(tls_sock.recv(1024).decode("utf-8"))

    def validate_server_certificate(self, cert: x509.Certificate):
        # Vérification du Common Name (CN) pour la validité
        common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert common_name == 'localhost', f"Invalid Common Name: {common_name}"

        # Autre vérification
        assert cert.not_valid_before < cert.not_valid_after, "Certificate is not yet valid!"
        assert cert.not_valid_after > datetime.now(), "Certificate has expired!"