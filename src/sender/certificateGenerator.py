from SS_certificate import SelfSignedcertificate

class CertificateGenerator:
    @staticmethod
    def generate_server_certificate(cert_file, key_file):
        # Instanciation de la class SelfSignedCertificate
        cert_generator = SelfSignedcertificate()

        # Generation de la clé privée et du certificat
        private_key, certificate = cert_generator.generate_self_signed_certificate()

        # Enregistrement dans un fichier
        with open(cert_file, "w") as cert_f:
            cert_f.write(certificate)
        with open(key_file, "w") as key_f:
            key_f.write(private_key)
        return certificate, private_key