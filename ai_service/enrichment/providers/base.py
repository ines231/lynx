from abc import ABC, abstractmethod
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class ThreatIntelligence:
    indicator: str
    indicator_type: str  # ip, domain, hash
    reputation_score: float  # 0-100
    is_malicious: bool
    source: str
    details: Dict[str, Any]

class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers"""
    
    @abstractmethod
    async def check_ip(self, ip: str) -> ThreatIntelligence:
        pass
    
    @abstractmethod
    async def check_domain(self, domain: str) -> ThreatIntelligence:
        pass
    
    @abstractmethod
    async def check_hash(self, file_hash: str) -> ThreatIntelligence:
        pass
