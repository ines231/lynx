from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from ai_service.correlation.kill_chain import kill_chain_correlator
from ai_service.reports.investigation_report import report_generator
from ai_service.hypotheses.hypothesis_generator import hypothesis_generator
from ai_service.ml.anomaly.anomaly_service import anomaly_service
from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh
from ai_service.enrichment.enrichment_service import enrichment_service
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/investigations", tags=["investigations"])

@router.get("/")
async def get_investigations_info():
    return {
        "message": "Investigations endpoint",
        "endpoints": [
            "POST /api/investigations/analyze-events - Analyze events and generate report",
            "GET /api/investigations/full-demo - Run full attack detection + reporting demo"
        ]
    }

@router.post("/analyze-events")
async def analyze_events(events_count: int = 50):
    """
    Analyze events, detect attacks, generate reports and hypotheses
    """
    try:
        logger.info("Step 1: Generating mock events...")
        events = mock_wazuh.generate_events(count=events_count)
        
        logger.info("Step 2: Enriching events...")
        enriched_events = []
        for event in events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_events.append(enriched_dict)
        
        logger.info("Step 3: Detecting anomalies...")
        anomalies = anomaly_service.detect_batch_anomalies(enriched_events)
        
        logger.info("Step 4: Correlating kill chain...")
        attacks = kill_chain_correlator.correlate_events(enriched_events)
        
        # Generate reports and hypotheses for each attack
        reports = []
        hypotheses_list = []
        
        for attack in attacks:
            logger.info(f"Generating report for attack {attack['attack_id']}...")
            report = report_generator.generate_report(attack)
            reports.append(report)
            
            logger.info(f"Generating hypotheses for attack {attack['attack_id']}...")
            hypotheses = hypothesis_generator.generate_hypotheses_from_attack(attack)
            hypotheses_list.extend(hypotheses)
        
        anomaly_count = sum(1 for a in anomalies if a["is_anomaly"])
        
        return {
            "status": "success",
            "summary": {
                "total_events": len(enriched_events),
                "anomalies_detected": anomaly_count,
                "attacks_found": len(attacks),
                "reports_generated": len(reports),
                "hypotheses_generated": len(hypotheses_list)
            },
            "reports": reports[:1] if reports else [],  # Return first report
            "hypotheses": hypotheses_list[:3] if hypotheses_list else []  # Return first 3
        }
    
    except Exception as e:
        logger.error(f"Error analyzing events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/full-demo")
async def full_demo():
    """
    Full end-to-end demo:
    1. Train detector
    2. Generate attack scenario
    3. Correlate kill chain
    4. Generate investigation reports
    5. Generate hunting hypotheses
    """
    try:
        logger.info("=== FULL INVESTIGATION DEMO ===")
        
        # Step 1: Train detector on normal events
        logger.info("Step 1: Training detector on normal events...")
        normal_events = mock_wazuh.generate_events(count=30)
        enriched_normal = []
        for event in normal_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_normal.append(enriched_dict)
        anomaly_service.train_detector(enriched_normal)
        
        # Step 2: Generate attack scenario
        logger.info("Step 2: Generating attack scenario...")
        attack_events = mock_wazuh.generate_attack_scenario()
        enriched_attack = []
        for event in attack_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_attack.append(enriched_dict)
        
        # Step 3: Detect anomalies
        logger.info("Step 3: Detecting anomalies...")
        anomalies = anomaly_service.detect_batch_anomalies(enriched_attack)
        anomaly_count = sum(1 for a in anomalies if a["is_anomaly"])
        
        # Step 4: Correlate kill chain
        logger.info("Step 4: Correlating kill chain...")
        attacks = kill_chain_correlator.correlate_events(enriched_attack)
        
        # Step 5: Generate investigation reports
        logger.info("Step 5: Generating investigation reports...")
        reports = []
        for attack in attacks:
            report = report_generator.generate_report(attack)
            reports.append(report)
        
        # Step 6: Generate hypotheses
        logger.info("Step 6: Generating hunting hypotheses...")
        hypotheses_list = []
        for attack in attacks:
            hypotheses = hypothesis_generator.generate_hypotheses_from_attack(attack)
            hypotheses_list.extend(hypotheses)
        
        # Also generate hypotheses from threat types
        logger.info("Step 7: Generating threat-based hypotheses...")
        threat_hypotheses = hypothesis_generator.generate_hypotheses_from_threat_intel("apt")
        
        logger.info("=== DEMO COMPLETE ===")
        
        return {
            "status": "success",
            "message": "Full investigation demo completed",
            "results": {
                "training": {"events": 30, "status": "completed"},
                "attack_scenario": {"events": len(attack_events)},
                "detection": {
                    "total_events": len(enriched_attack),
                    "anomalies": anomaly_count,
                    "attacks_found": len(attacks)
                },
                "reporting": {
                    "investigation_reports": len(reports),
                    "hypotheses_generated": len(hypotheses_list) + len(threat_hypotheses)
                }
            },
            "sample_report": reports[0] if reports else None,
            "sample_hypotheses": hypotheses_list[:2] if hypotheses_list else [],
            "threat_hypotheses": threat_hypotheses[:2] if threat_hypotheses else []
        }
    
    except Exception as e:
        logger.error(f"Demo error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
