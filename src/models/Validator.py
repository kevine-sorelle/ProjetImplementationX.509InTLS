from cryptography import x509


class Validator:
    def __init__(self, name, value, type, certificate):
        self.name = name
        self.value = value
        self.type = type
        self.certificate = certificate

    def validate(self, cert: x509.Certificate):
        pass