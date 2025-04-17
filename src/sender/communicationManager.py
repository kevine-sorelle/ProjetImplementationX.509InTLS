import sys
sys.path.append("src")
from server import Server
from config.config import CERT_FILE, KEY_FILE
from sender.certificateGenerator import CertificateGenerator
from sender.client import Client


class CommunicationManager:
    @staticmethod
    def start_tls_server():
        comm = CertificateGenerator.generate_server_certificate(CERT_FILE, KEY_FILE)

        # Demarrage du serveur
        server = Server()
        server.start_server(comm[0], comm[1])

    @staticmethod
    def start_tls_client():
        # Demarrage du client
        client = Client()
        client.create_client()