import ssl
import socket
import sys
sys.path.append("src")
from models.IConnectionManager import IConnectionManager
from models.ICertificateFetcher import ICertificateFetcher


class GetCertificate:
    def __init__(self, connection: IConnectionManager, fetcher: ICertificateFetcher):
        self._connection = connection
        self._fetcher = fetcher

    # Obtient le nom du serveur
    @property
    def connection(self):
        return self._connection

    # Définit un nouveau serveur
    @connection.setter
    def connection(self, newConnection: IConnectionManager):
        self._connection = newConnection

    # Obtient le numéro de port
    @property
    def fetcher(self):
        return self._fetcher

    # Définit un nouveau port pour le serveur
    @fetcher.setter
    def fetcher(self, newFetcher: ICertificateFetcher):
        self._fetcher = newFetcher

    def getCertificate(self):
        """Retrieve the x.509 certificate from a remote server using SSL."""
        return self._fetcher.fetchCertificate(self._connection.hostname, self._connection.port)
