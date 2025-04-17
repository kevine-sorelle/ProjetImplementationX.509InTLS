import ssl
import socket
import OpenSSL
from cryptography import x509
import sys
sys.path.append("src")
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from typing import Dict, List, Optional, Tuple
from strategy.SignatureStrategyFactory import SignatureStrategyFactory
from utils.logger_config import setup_logger
from utils.certificate_parser import CertificateParser
from cryptography.hazmat.primitives.asymmetric import padding
logger = setup_logger(__name__)

class CertificateChainService:
    def __init__(self):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.cert_parser = CertificateParser()

    def get_certificate_chain(self, hostname: str, port: int) -> Tuple[List[x509.Certificate], Optional[str]]:
        """
        Get the complete certificate chain for a server.
        
        Args:
            hostname: The hostname to get certificates for
            port: The port to connect to
            
        Returns:
            Tuple containing:
            - List of x509.Certificate objects in the chain
            - Raw PEM string of the entire chain (or None if not available)
        """
        ssl_socket = None
        try:
            # Create connection to get the certificate chain
            sock = socket.create_connection((hostname, port))
            ssl_socket = self.context.wrap_socket(sock, server_hostname=hostname)

            # Get the certificate chain using OpenSSL
            cert_chain = []
            pem_chain = ""
            
            # Get the leaf certificate
            der_cert = ssl_socket.getpeercert(binary_form=True)
            logger.info("der_cert length: %s", len(der_cert))
            if der_cert:
                # Convert binary certificate to x509.Certificate
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                logger.info("cert subject: %s", cert.subject)
                cert_chain.append(cert)
                logger.info("cert_chain length: %s", len(cert_chain))
                pem_chain += cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
                logger.info("pem_chain length: %s", len(pem_chain))

            try:
                # Create a new SSL connection
                logger.info("Creating new SSL connection")
                sock2 = socket.create_connection((hostname, port))
                ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
                ssl_conn = OpenSSL.SSL.Connection(ctx, sock2)
                ssl_conn.set_tlsext_host_name(hostname.encode())
                ssl_conn.set_connect_state()
                ssl_conn.do_handshake()
                logger.info("SSL connection created")
                # Get the certificate chain
                chain = ssl_conn.get_peer_cert_chain()
                logger.info("chain length: %s", len(chain))

                if chain:
                    for cert in chain[1:]: # Skip the leaf certificate
                        der_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        cert_chain.append(cert)
                        logger.info("Added certificate to chain: %s", cert.subject)
                        logger.info("Certificate chain: length: %d", len(cert_chain))
                        pem_chain += cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
                ssl_conn.close()
                sock2.close()
            except Exception as e:
                logger.error("Error creating SSL connection and getting certificate chain: %s", str(e))
                
            return cert_chain, pem_chain if pem_chain else None, ssl_socket
        except ssl.SSLError as e:
            logger.error("SSL error while fetching certificate chain: %s", str(e))
            raise
        except socket.error as e:
            logger.error("Socket error while fetching certificate chain: %s", str(e))
            raise
        except Exception as e:
            logger.error("Unexpected error while fetching certificate chain: %s", str(e))
            raise
        finally:
            pass

    def _convert_chain_to_pem(self, der_chain: List[bytes]) -> str:
        """Convert a list of DER-encoded certificates to PEM format."""
        pem_chain = ""
        for der_cert in der_chain:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            pem_cert = cert.public_bytes(encoding=ssl.PEM).decode('utf-8')
            pem_chain += pem_cert + "\n"
        return pem_chain

    def validate_chain(self, cert_chain: List[x509.Certificate]) -> List[Dict]:
        """
        Validate the certificate chain.
        
        Args:
            cert_chain: List of certificates in the chain
            
        Returns:
            bool: True if the chain is valid, False otherwise
        """
        validation_results = []
        if not cert_chain:
            logger.warning("Certificate chain is empty")
            return False

        try:
            # For self-signed certificates
            if len(cert_chain) == 1:
                cert = cert_chain[0]
                # Verify self-signed certificate
                signatureStrategy = SignatureStrategyFactory.get_signature_strategy(cert, cert)
                valid, error = signatureStrategy.validate_signature(cert, cert)
                logger.info(f"Self-signed certificate verification: {valid} {error}")
                if not valid:
                    logger.error(f"Self-signed certificate verification failed: {error}")
                    valid, error = False, f"Self-signed certificate verification failed"
                validation_results.append({
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "valid": valid,
                    "error": None if valid else error
                })
                return validation_results

            # For multi-certificate chains
            for i in range(len(cert_chain) - 1):
                cert = cert_chain[i]
                issuer = cert_chain[i + 1]
                logger.info(f"Verifying: {cert.subject} <- {issuer.subject}")
                try:
                    signatureStrategy = SignatureStrategyFactory.get_signature_strategy(cert, issuer)
                    valid, error = signatureStrategy.validate_signature(cert, issuer)
                    logger.info(f"Certificate verification: {valid} {error}")
                except Exception as e:
                    valid, error = False, f"Error validating certificate chain: {str(e)}"
                if not valid:
                    logger.error(f"Certificate verification failed: {error}")
                    valid, error = False,  f"Error validating certificate chain"
                validation_results.append({
                    "subject": str(cert.subject),
                    "issuer": str(issuer.subject),
                    "valid": valid,
                    "error": None if valid else error
                })
            return validation_results

        except Exception as e:
            logger.error(f"Error validating certificate chain: {str(e)}")
            return [
                {
                    "subject": "Unknown",
                    "issuer": "Unknown",
                    "valid": False,
                    "error": f"Error validating certificate chain: {str(e)}"
                }
            ]