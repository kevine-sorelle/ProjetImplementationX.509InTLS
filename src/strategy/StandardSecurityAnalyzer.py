import socket
import ssl
import sys
sys.path.append("src")
from typing import Dict, Optional
from strategy.SecurityAnalysisStrategy import SecurityAnalysisStrategy
from utils.logger_config import setup_logger



# Set up logger for this module
logger = setup_logger(__name__)


class StandardSecurityAnalyzer(SecurityAnalysisStrategy):
    """Analyzes server security using standard connection"""
    
    def __init__(self):
        super().__init__()

    def analyze_security(self, hostname: str, port: int, certificate: Optional[object] = None) -> Dict:
        """Analyze server security using standard connection"""
        try:
            self._validate_inputs(hostname, port, certificate)
            return self.security_analysis_orchestrator.analyze_server_security(hostname, port)
        except Exception as e:
            return self._create_error_response(str(e))

    def _validate_inputs(self, hostname: str, port: int, certificate: Optional[object] = None):
        """Validate inputs for the security analysis"""
        if not hostname:
            raise ValueError("Hostname is required")
        if not port:
            raise ValueError("Port is required")
            
