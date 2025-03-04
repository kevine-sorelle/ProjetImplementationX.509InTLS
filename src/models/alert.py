import sys
sys.path.append("src")
from constants import DANGER, ATTENTION, SUCCESS

class Alert():
    def __init__(self, type, message, timestamp, isActive, certificat):
        self.type = type
        self.message = message
        self.timestamp = timestamp
        self.isActive = isActive
        self.certificat = certificat

    def __str__(self):
        return f"{self.timestamp}: {self.certificat} pour le certificat {self.certificat}"