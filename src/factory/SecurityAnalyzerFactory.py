import sys
sys.path.append("src")

from strategy.CertificateBasedAnalyzer import CertificateBasedAnalyzer
from strategy.StandardSecurityAnalyzer import StandardSecurityAnalyzer
from strategy.SecurityAnalysisStrategy import SecurityAnalysisStrategy
from typing import Type, List, Dict, Optional


class SecurityAnalyzerFactory:
    _analyzers = {
        'standard': StandardSecurityAnalyzer,
        'certificate': CertificateBasedAnalyzer
    }

    @classmethod
    def register_analyzer(cls, name: str, analyzer_class: Type[SecurityAnalysisStrategy]) -> None:
        cls._analyzers[name] = analyzer_class

    @classmethod
    def create_analyzer(cls, analyzer_type: str) -> SecurityAnalysisStrategy:
        analyzer_class = cls._analyzers.get(analyzer_type)
        if not analyzer_class:
            raise ValueError(f"Invalid analyzer type: {analyzer_type}")
        return analyzer_class()
    
