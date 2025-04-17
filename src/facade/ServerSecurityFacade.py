from typing import Dict, Optional
import sys
sys.path.append("src")
from builder.SecurityReportBuilder import SecurityReportBuilder
from factory.SecurityAnalyzerFactory import SecurityAnalyzerFactory
from services.CertificateChainService import CertificateChainService
from services.CertificateInfoExtractor import CertificateInfoExtractor
from services.OCSPChecker import OCSPChecker
from services.SecurityRecommendationGenerator import SecurityRecommendationGenerator
from utils.logger_config import setup_logger

logger = setup_logger(__name__)

class ServerSecurityFacade:
    def __init__(self):
        self._analyzer_factory = SecurityAnalyzerFactory()
        self._report_builder = SecurityReportBuilder()
        self._cert_chain_service = CertificateChainService()

    def analyze_server(self, hostname: str, port: int = 443, certificate: Optional[object] = None) -> Dict:
        try:
            logger.debug(f"Analyzing server: {hostname}:{port}")
            logger.debug(f"Certificate type: {type(certificate)}")
            
            # Get certificate chain if no certificate provided
            if not certificate:
                logger.debug("No certificate provided, fetching from server")
                cert_chain = self._cert_chain_service.get_certificate_chain(hostname, port)
                certificate = cert_chain[0] if cert_chain else None
                if not certificate:
                    raise ValueError("Could not obtain certificate from server")

            # Choose appropriate analyzer
            analyzer_type = 'certificate' if certificate else 'standard'
            logger.debug(f"Using analyzer type: {analyzer_type}")
            analyzer = self._analyzer_factory.create_analyzer(analyzer_type)
            
            # Perform analysis
            analysis_result = analyzer.analyze_security(hostname, port, certificate)
            logger.debug("Analysis completed successfully")
            
            # Build report
            return self._report_builder\
                .add_server_info(analysis_result.get('server_info', {}))\
                .add_validation_results(analysis_result.get('validation_results', {}))\
                .add_security_recommendations(analysis_result.get('security_recommendations', []))\
                .build()
                
        except Exception as e:
            logger.error(f"Error in analyze_server: {str(e)}", exc_info=True)
            return self._report_builder\
                .add_error(str(e))\
                .build()

    def _count_valid_certificates(self, validation_results: Dict) -> int:
        return 1 if all(result.get('valid', False) for result in validation_results.values()) else 0

    def _count_invalid_certificates(self, validation_results: Dict) -> int:
        return 1 if not all(result.get('valid', False) for result in validation_results.values()) else 0
        
