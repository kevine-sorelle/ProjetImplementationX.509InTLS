from enum import Enum

class CertificateMessage(Enum):
    # Message de validité des certificats
    DANGER = "Certificat expiré"
    ATTENTION = "Période de validité insuffisante"
    SUCCES = "Certificat valide"

    # Affichage de l'émetteur du certificat
    EMETTEUR_VALIDE = "Certificat valide émis par: "
    EMETTEUR_INVALIDE = "Émetteur invalide!"