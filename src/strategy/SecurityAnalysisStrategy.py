from abc import ABC, abstractmethod
from dataclasses import dataclass
import sys
sys.path.append("src")
from services.SecurityAnalysisOrchestrator import SecurityAnalysisOrchestrator
from services.CertificateInfoExtractor import CertificateInfoExtractor
from services.OCSPChecker import OCSPChecker
from services.SecurityRecommendationGenerator import SecurityRecommendationGenerator
from typing import List, Dict, Optional
from models.ValidationStrategy import ValidationStrategy
from models.SSLConnectionManager import SSLConnectionManager
from models.SSLCertificateFetcher import SSLCertificateFetcher
from utils.certificate_parser import CertificateParser
import socket
import ssl
from utils.logger_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

class SecurityAnalysisStrategy(ABC):
    """Abstract base class defining the interface for security analysis"""
    
    def __init__(self):
        self.security_analysis_orchestrator = SecurityAnalysisOrchestrator()

    @abstractmethod
    def analyze_security(self, hostname: str, port: int, certificate: Optional[object] = None) -> Dict:
        pass

    @abstractmethod
    def _validate_inputs(self, hostname: str, port: int):
        pass

    def _create_error_response(self, error_message: str) -> Dict:
        return{
            'error': error_message,
            'server_info': None,
            'validation_results': {},
            'security_recommendations': []
        }
