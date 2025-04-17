import socket
import ssl
import sys
sys.path.append("src")
from config.config import SOCKET_SERVER_HOST, SOCKET_SERVER_PORT


class Server:
    @staticmethod
    def start_server(cert_file, key_file):
        # Initialisation de la socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((SOCKET_SERVER_HOST, SOCKET_SERVER_PORT))
        server_socket.listen(5)

        # Configuration du serveur TLS
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Acceptation de la connection client
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connexion établie avec {addr}")

            # Wrap socket with SSL
            with context.wrap_socket(client_socket, server_side=True) as tls_socket:
                print("Connexion TLS établie.")
                data = tls_socket.recv(1024)
                print("Message du client : ", data.decode("utf-8"))
                tls_socket.send(b"Hello from the server!")


