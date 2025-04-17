from abc import ABC, abstractmethod
class IConnectionManager(ABC):
    """Classe de base abstraite pour tout type de connection."""

    @property
    @abstractmethod
    def hostname(self):
        """Recupère le nom du serveur distant."""
        pass

    @hostname.setter
    @abstractmethod
    def hostname(self, value):
        """Modifie le nom du serveur distant."""
        pass

    @property
    @abstractmethod
    def port(self):
        """Recupère le numéro de port de la connexion."""
        pass

    @port.setter
    @abstractmethod
    def port(self, newPort):
        """Modifie le numéro de la connexion."""
        pass