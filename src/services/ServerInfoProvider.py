import socket
import ssl
from typing import Dict, Optional
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class ServerInfoProvider:
    def __init__(self):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def get_server_info(self, hostname: str, port: int) -> Dict:
        """Get server connection information including protocol version and cipher."""
        ssl_socket = None
        try:
            # Basic connection info
            server_info = {
                'hostname': hostname,
                'port': port,
                'ip_address': socket.gethostbyname(hostname)
            }

            # SSL/TLS connection info
            sock = socket.create_connection((hostname, port))
            ssl_socket = self.context.wrap_socket(sock, server_hostname=hostname)
            
            # Add SSL/TLS specific information
            server_info.update({
                'protocol_version': ssl_socket.version(),
                'cipher': ssl_socket.cipher()[0] if ssl_socket.cipher() else None,
                'supported_protocols': self._get_supported_protocols(hostname, port),
                'supports_ocsp_stapling': self._check_ocsp_stapling(ssl_socket)
            })

            return server_info

        except socket.gaierror as e:
            logger.error(f"DNS lookup failed for {hostname}: {str(e)}")
            raise
        except socket.error as e:
            logger.error(f"Connection failed to {hostname}:{port}: {str(e)}")
            raise
        except ssl.SSLError as e:
            logger.error(f"SSL error occurred: {str(e)}")
            raise
        finally:
            if ssl_socket:
                ssl_socket.close()

    def _get_supported_protocols(self, hostname: str, port: int) -> list:
        """Check which TLS versions are supported by the server."""
        supported = []
        protocols = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        
        for protocol in protocols:
            try:
                context = ssl.SSLContext()
                context.minimum_version = getattr(ssl.TLSVersion, protocol.replace('.', '_'))
                context.maximum_version = getattr(ssl.TLSVersion, protocol.replace('.', '_'))
                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                        supported.append(protocol)
            except:
                continue
        return supported

    def _check_ocsp_stapling(self, ssl_socket) -> bool:
        """Check if OCSP stapling is supported."""
        try:
            return ssl_socket.get_ocsp_response() is not None
        except:
            return False 