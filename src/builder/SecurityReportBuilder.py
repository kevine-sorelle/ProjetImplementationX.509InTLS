from dataclasses import dataclass
from typing import List, Dict, Optional
import sys
sys.path.append("src")
from builder.SecurityReport import SecurityReport


class SecurityReportBuilder:
    def __init__(self):
        self._server_info = {}
        self._validation_results = {}
        self._security_recommendations = []
        self._error = None

    def add_server_info(self, server_info: dict) -> 'SecurityReportBuilder':
        self._server_info = server_info
        return self
    
    def add_validation_results(self, results: dict) -> 'SecurityReportBuilder':
        self._validation_results = results
        return self
    
    def add_security_recommendations(self, recommendations: list) -> 'SecurityReportBuilder':
        self._security_recommendations = recommendations
        return self

    def add_error(self, error: str) -> 'SecurityReportBuilder':
        self._error = error
        return self

    def build(self) -> Dict:
        report = SecurityReport(
            server_info=self._server_info,
            validation_results=self._validation_results,
            security_recommendations=self._security_recommendations,
            error=self._error
        )
        return report.to_dict() # Convert to dictionary


    def reset(self) -> None:
        self.__init__()

