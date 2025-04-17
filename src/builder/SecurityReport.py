from dataclasses import asdict, dataclass
from typing import Dict, List, Optional
import json
@dataclass
class SecurityReport:
    server_info: Dict
    validation_results: Dict
    security_recommendations: List
    error: Optional[str] = None

    def __getitem__(self, key: str):
        """Allow dictionary-like access to report fields"""
        return asdict(self)[key]
    
    def __setitem__(self, key: str, value):
        """Allow dictionary-like assignment to report fields"""
        setattr(self, key, value)

    def get(self, key, default=None):
        """Mimic dictionary get() method"""
        try:
            return self[key]
        except KeyError:
            return default
        
    def to_dict(self):
        """Convert report to dictionary"""
        return asdict(self)
    
    def to_json(self):
        """Convert report to JSON string"""
        return json.dumps(self.to_dict())
        
