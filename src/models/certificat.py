"""Classe pour stocker les informations d'un certificat."""
from cryptography import x509


class Certificat:
    # Constructeur d'initialisation des données du certificat
    def __init__(self, id_cert, nom, date_debut, date_fin, approche, etat, type_cert):
        self._id_cert = id_cert
        self.nom = nom
        self.date_debut = date_debut
        self.date_fin = date_fin
        self.approche = approche
        self.etat = etat
        self.type_cert = type_cert

    # Obtient la valeur de l'id du certificat
    @property
    def id_cert(self):
        return self.id_cert

    # Modifie la valeur de l'id du certificat
    @id_cert.setter
    def id_cert(self, value):
        self.id_cert = value

    # Valide les données d'un certificat
    def validate(self):
        pass

    def get_public_key(self, cert: x509.Certificate):
        """Extrait la clé public d'un certificat.'"""
        return cert.public_key()