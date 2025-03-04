class SSLConnectionManager:
    """Handles SSL connection settings and hostname/port storage."""

    def __init__(self, hostname, port):
        self._hostname = hostname
        self._port = port

    # Obtient le nom du serveur
    @property
    def hostname(self):
        return self._hostname

    # Définit un nouveau serveur
    @hostname.setter
    def hostname(self, newHostname):
        self._hostname = newHostname

    # Obtient le numéro de port
    @property
    def port(self):
        return self._port

    # Définit un nouveau port pour le serveur
    @port.setter
    def port(self, newPort):
        self._port = newPort