from .base import ThreatIntelProvider, ThreatIntelligence
import random

class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock provider for testing without API keys"""
    
    async def check_ip(self, ip: str) -> ThreatIntelligence:
        is_malicious = ip.startswith("192.168.1.13") or random.random() < 0.1
        
        return ThreatIntelligence(
            indicator=ip,
            indicator_type="ip",
            reputation_score=75.0 if is_malicious else 5.0,
            is_malicious=is_malicious,
            source="mock_provider",
            details={
                "country": "Unknown",
                "asn": "AS0000",
                "reports": random.randint(0, 10) if is_malicious else 0
            }
        )
    
    async def check_domain(self, domain: str) -> ThreatIntelligence:
        is_malicious = "malware" in domain.lower() or random.random() < 0.05
        
        return ThreatIntelligence(
            indicator=domain,
            indicator_type="domain",
            reputation_score=80.0 if is_malicious else 2.0,
            is_malicious=is_malicious,
            source="mock_provider",
            details={
                "age_days": random.randint(1, 3650),
                "registrar": "Unknown",
                "categories": ["malware"] if is_malicious else ["legitimate"]
            }
        )
    
    async def check_hash(self, file_hash: str) -> ThreatIntelligence:
        is_malicious = file_hash.startswith("666") or random.random() < 0.05
        
        return ThreatIntelligence(
            indicator=file_hash,
            indicator_type="hash",
            reputation_score=90.0 if is_malicious else 1.0,
            is_malicious=is_malicious,
            source="mock_provider",
            details={
                "detections": random.randint(0, 60) if is_malicious else 0,
                "vendors": "Unknown"
            }
        )
