from typing import Dict, Any
from .providers.mock_provider import MockThreatIntelProvider
import logging

logger = logging.getLogger(__name__)

class EnrichmentService:
    def __init__(self):
        self.ti_provider = MockThreatIntelProvider()
    
    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich security event with threat intelligence"""
        enriched = event.copy()
        enriched["threat_intel"] = {}
        
        # Check source IP
        if "source_ip" in event:
            ip_ti = await self.ti_provider.check_ip(event["source_ip"])
            enriched["threat_intel"]["source_ip"] = {
                "reputation_score": ip_ti.reputation_score,
                "is_malicious": ip_ti.is_malicious,
                "details": ip_ti.details
            }
        
        # Check destination IP
        if "destination_ip" in event:
            ip_ti = await self.ti_provider.check_ip(event["destination_ip"])
            enriched["threat_intel"]["destination_ip"] = {
                "reputation_score": ip_ti.reputation_score,
                "is_malicious": ip_ti.is_malicious,
                "details": ip_ti.details
            }
        
        return enriched
