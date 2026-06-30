from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any
from ai_service.ml.anomaly.anomaly_service import anomaly_service
from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh
from ai_service.enrichment.enrichment_service import enrichment_service
from ai_service.connectors.models.event import SecurityEvent
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/anomalies", tags=["anomalies"])

@router.get("/")
async def get_anomalies_info():
    """Get information about anomalies endpoint"""
    return {
        "message": "Anomaly detection endpoint",
        "endpoints": [
            "GET /api/anomalies/status - Get detector status",
            "POST /api/anomalies/train - Train detector",
            "POST /api/anomalies/detect - Detect anomaly in single event",
            "POST /api/anomalies/detect-batch - Detect anomalies in batch",
            "GET /api/anomalies/demo - Run demo with sample data",
        ]
    }

@router.get("/status")
async def get_status():
    """Get anomaly detector status"""
    status = anomaly_service.get_detector_status()
    return {
        "service": "anomaly_detection",
        "status": status
    }

@router.post("/train")
async def train_detector(event_count: int = 100):
    """
    Train anomaly detector on mock data
    
    This should only be done once with historical data
    In production, this would be historical security events from Wazuh
    """
    try:
        # Generate sample events
        logger.info(f"Generating {event_count} events for training...")
        events = mock_wazuh.generate_events(count=event_count)
        
        # Enrich events
        logger.info("Enriching events with threat intelligence...")
        enriched_events = []
        for event in events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {
                    k: v.dict() for k, v in enriched.threat_intel.items()
                }
            }
            enriched_events.append(enriched_dict)
        
        # Train detector
        logger.info("Training Isolation Forest detector...")
        result = anomaly_service.train_detector(enriched_events)
        
        return {
            "status": "success",
            "message": "Detector trained successfully",
            "training_result": result,
            "detector_status": anomaly_service.get_detector_status()
        }
    except Exception as e:
        logger.error(f"Error training detector: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detect")
async def detect_anomaly(event: SecurityEvent):
    """Detect anomaly in a single security event"""
    try:
        # Enrich event
        enriched = await enrichment_service.enrich_event(event)
        event_dict = {
            **enriched.event.dict(),
            "threat_intel": {
                k: v.dict() for k, v in enriched.threat_intel.items()
            }
        }
        
        # Detect anomaly
        result = anomaly_service.detect_anomaly(event_dict)
        
        return {
            "status": "success",
            "anomaly_result": result
        }
    except Exception as e:
        logger.error(f"Error detecting anomaly: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detect-batch")
async def detect_batch_anomalies(events: List[SecurityEvent]):
    """Detect anomalies in batch of events"""
    try:
        # Enrich events
        enriched_events = await enrichment_service.enrich_events(events)
        
        event_dicts = []
        for enriched in enriched_events:
            event_dict = {
                **enriched.event.dict(),
                "threat_intel": {
                    k: v.dict() for k, v in enriched.threat_intel.items()
                }
            }
            event_dicts.append(event_dict)
        
        # Detect anomalies
        results = anomaly_service.detect_batch_anomalies(event_dicts)
        
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        
        return {
            "status": "success",
            "total_events": len(events),
            "anomalies_found": anomaly_count,
            "results": results
        }
    except Exception as e:
        logger.error(f"Error detecting batch anomalies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/demo")
async def run_demo():
    """
    Run a full demo:
    1. Train detector on sample events
    2. Generate attack scenario
    3. Detect anomalies in attack
    """
    try:
        # Step 1: Train on normal events
        logger.info("Demo: Step 1 - Training on normal events...")
        normal_events = mock_wazuh.generate_events(count=50)
        enriched_normal = []
        for event in normal_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {
                    k: v.dict() for k, v in enriched.threat_intel.items()
                }
            }
            enriched_normal.append(enriched_dict)
        
        anomaly_service.train_detector(enriched_normal)
        logger.info("Demo: Detector trained on 50 normal events")
        
        # Step 2: Generate attack scenario
        logger.info("Demo: Step 2 - Generating attack scenario...")
        attack_events = mock_wazuh.generate_attack_scenario()
        
        # Step 3: Enrich and detect anomalies
        logger.info("Demo: Step 3 - Detecting anomalies in attack scenario...")
        enriched_attack = []
        for event in attack_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {
                    k: v.dict() for k, v in enriched.threat_intel.items()
                }
            }
            enriched_attack.append(enriched_dict)
        
        attack_results = anomaly_service.detect_batch_anomalies(enriched_attack)
        
        anomaly_count = sum(1 for r in attack_results if r["is_anomaly"])
        
        return {
            "status": "success",
            "message": "Demo completed successfully",
            "steps": {
                "training": {
                    "events": 50,
                    "message": "Detector trained on normal events"
                },
                "attack_scenario": {
                    "events": len(attack_events),
                    "stages": ["reconnaissance", "exploitation", "persistence", "lateral_movement", "exfiltration"]
                },
                "detection": {
                    "total_events": len(attack_events),
                    "anomalies_detected": anomaly_count,
                    "detection_rate": f"{(anomaly_count / len(attack_events) * 100):.1f}%"
                }
            },
            "anomalies": attack_results
        }
    except Exception as e:
        logger.error(f"Error running demo: {e}")
        raise HTTPException(status_code=500, detail=str(e))
