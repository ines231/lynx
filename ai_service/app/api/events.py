from fastapi import APIRouter, HTTPException
from ai_service.connectors.models.event import SecurityEvent, EnrichedEvent
from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh
from ai_service.enrichment.enrichment_service import enrichment_service
from typing import List
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/events", tags=["events"])

@router.get("/")
async def get_events_info():
    """Get information about events endpoint"""
    return {
        "message": "Events endpoint",
        "endpoints": [
            "GET /api/events/sample - Get sample mock events",
            "GET /api/events/attack-scenario - Get realistic attack scenario",
            "POST /api/events/enrich - Enrich event with threat intel",
            "POST /api/events/enrich-batch - Enrich multiple events"
        ]
    }

@router.get("/sample", response_model=List[SecurityEvent])
async def get_sample_events(count: int = 10):
    """
    Get sample mock security events
    
    Params:
    - count: Number of events to generate (default: 10)
    """
    try:
        events = mock_wazuh.generate_events(count=count)
        logger.info(f"Generated {count} sample events")
        return events
    except Exception as e:
        logger.error(f"Error generating events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/attack-scenario", response_model=List[SecurityEvent])
async def get_attack_scenario():
    """
    Get a realistic attack scenario following the kill chain:
    Reconnaissance -> Exploitation -> Persistence -> Lateral Movement -> Exfiltration
    """
    try:
        events = mock_wazuh.generate_attack_scenario()
        logger.info("Generated attack scenario")
        return events
    except Exception as e:
        logger.error(f"Error generating attack scenario: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enrich", response_model=EnrichedEvent)
async def enrich_event(event: SecurityEvent):
    """
    Enrich a single security event with threat intelligence
    """
    try:
        enriched = await enrichment_service.enrich_event(event)
        logger.info(f"Enriched event: {event.event_type}")
        return enriched
    except Exception as e:
        logger.error(f"Error enriching event: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enrich-batch", response_model=List[EnrichedEvent])
async def enrich_batch(events: List[SecurityEvent]):
    """
    Enrich multiple security events with threat intelligence
    """
    try:
        enriched_events = await enrichment_service.enrich_events(events)
        logger.info(f"Enriched {len(enriched_events)} events")
        return enriched_events
    except Exception as e:
        logger.error(f"Error enriching events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ingest", response_model=dict)
async def ingest_event(event: SecurityEvent):
    """
    Ingest and enrich a security event from Wazuh
    This would be called by actual Wazuh in production
    """
    try:
        enriched = await enrichment_service.enrich_event(event)
        logger.info(f"Ingested and enriched: {event.event_type}")
        return {
            "status": "success",
            "message": "Event ingested and enriched",
            "event_id": str(event.timestamp),
            "threat_intel_count": len(enriched.threat_intel)
        }
    except Exception as e:
        logger.error(f"Error ingesting event: {e}")
        raise HTTPException(status_code=500, detail=str(e))
