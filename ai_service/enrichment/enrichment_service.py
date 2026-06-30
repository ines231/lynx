from ai_service.connectors.models.event import SecurityEvent, EnrichedEvent, ThreatIntelResult
from ai_service.connectors.intelowl.mock_intelowl import mock_intelowl
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class EnrichmentService:
    """Service to enrich security events with threat intelligence"""
    
    def __init__(self, intelowl_connector=None):
        self.intelowl = intelowl_connector or mock_intelowl
    
    async def enrich_event(self, event: SecurityEvent) -> EnrichedEvent:
        """
        Enrich a security event with threat intelligence
        
        Checks:
        - Source IP reputation
        - Destination IP reputation
        - File hash (if available)
        - Domain/URL in metadata
        """
        threat_intel = {}
        
        # Check source IP
        if event.source_ip:
            try:
                source_result = await self.intelowl.check_ip(event.source_ip)
                threat_intel["source_ip"] = source_result
                logger.debug(f"Enriched source IP: {event.source_ip}")
            except Exception as e:
                logger.error(f"Failed to check source IP {event.source_ip}: {e}")
        
        # Check destination IP
        if event.destination_ip:
            try:
                dest_result = await self.intelowl.check_ip(event.destination_ip)
                threat_intel["destination_ip"] = dest_result
                logger.debug(f"Enriched destination IP: {event.destination_ip}")
            except Exception as e:
                logger.error(f"Failed to check destination IP {event.destination_ip}: {e}")
        
        # Check file hash
        if event.file_hash:
            try:
                hash_result = await self.intelowl.check_hash(event.file_hash)
                threat_intel["file_hash"] = hash_result
                logger.debug(f"Enriched file hash: {event.file_hash[:16]}...")
            except Exception as e:
                logger.error(f"Failed to check file hash: {e}")
        
        # Check URLs in command line or metadata
        if event.command_line and ("http://" in event.command_line or "https://" in event.command_line):
            import re
            urls = re.findall(r'https?://[^\s]+', event.command_line)
            for url in urls[:1]:  # Check first URL only
                try:
                    url_result = await self.intelowl.check_url(url)
                    threat_intel["url"] = url_result
                except Exception as e:
                    logger.error(f"Failed to check URL: {e}")
        
        enriched = EnrichedEvent(
            event=event,
            threat_intel=threat_intel
        )
        
        logger.info(f"Enriched event: {event.event_type} from {event.source_ip}")
        return enriched
    
    async def enrich_events(self, events: list) -> list:
        """Enrich multiple events"""
        enriched_events = []
        for event in events:
            enriched = await self.enrich_event(event)
            enriched_events.append(enriched)
        
        logger.info(f"Enriched {len(enriched_events)} events")
        return enriched_events

# Singleton instance
enrichment_service = EnrichmentService()
