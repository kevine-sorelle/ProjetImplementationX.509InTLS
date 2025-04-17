import sys
sys.path.append("src")
from config import CERT_FILE, KEY_FILE
import threading
from sender import server
from sender.certificateGenerator import CertificateGenerator
from sender.communicationManager import CommunicationManager

if __name__ == '__main__':
    print("Communication Client / Server")
    cert = CertificateGenerator.generate_server_certificate(CERT_FILE, KEY_FILE)
    server = CommunicationManager().start_tls_server()


    # Etape 2: Demarrage du serveur
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()

    # Etape 3: Demarrage du client
    client = CommunicationManager().start_tls_client()

