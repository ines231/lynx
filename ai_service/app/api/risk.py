from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import logging
import traceback

from ai_service.risk.baseline_model import baseline_model
from ai_service.risk.anomaly_probability import anomaly_probability
from ai_service.risk.chi_square_tests import chi_square_tests
from ai_service.risk.monte_carlo_fair import monte_carlo_fair
from ai_service.risk.risk_treatment import risk_treatment

from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh
from ai_service.enrichment.enrichment_service import enrichment_service
from ai_service.correlation.kill_chain import kill_chain_correlator
from ai_service.reports.investigation_report import report_generator
from ai_service.hypotheses.hypothesis_generator import hypothesis_generator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/risk", tags=["risk"])

@router.get("/")
async def get_risk_info():
    return {
        "service": "Probabilistic FAIR Risk Engine",
        "version": "0.1.0",
        "endpoints": [
            "GET /api/risk/demo - Full risk engine demo",
            "GET /api/risk/analyze - Complete risk analysis",
            "POST /api/risk/calculate-risk - Risk for single event"
        ]
    }

@router.get("/demo")
async def risk_engine_demo():
    """Complete risk engine demo"""
    try:
        logger.info("=== RISK ENGINE DEMO START ===")
        
        # Build baseline
        logger.info("Step 1: Building baseline on 30 normal events...")
        normal_events = mock_wazuh.generate_events(count=30)
        enriched_normal = []
        for event in normal_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_normal.append(enriched_dict)
        
        baseline = baseline_model.build_user_baseline("demo_user", enriched_normal)
        
        # Generate attack
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
        
        # Analyze risk
        logger.info("Step 3: Calculating risk for each event...")
        event_analyses = []
        highest_risk = None
        
        for event in enriched_attack:
            anomaly_prob, _ = anomaly_probability.calculate_probability(event, baseline)
            risk_metrics = monte_carlo_fair.calculate_risk(event, anomaly_prob)
            treatment = risk_treatment.recommend_treatment(risk_metrics, event)
            
            analysis = {
                "event_type": event.get("event_type"),
                "anomaly_probability": float(anomaly_prob),
                "annual_loss_expectancy": float(risk_metrics.get("annual_loss_expectancy", 0)),
                "priority": treatment.get("priority"),
                "strategy": treatment.get("strategy")
            }
            event_analyses.append(analysis)
            
            ale = risk_metrics.get("annual_loss_expectancy", 0)
            if not highest_risk or ale > highest_risk["ale"]:
                highest_risk = {
                    "event": analysis,
                    "ale": ale,
                    "treatment": treatment
                }
        
        # Correlate
        logger.info("Step 4: Correlating kill chain...")
        attacks = kill_chain_correlator.correlate_events(enriched_attack)
        
        # Reports
        logger.info("Step 5: Generating investigation reports...")
        reports = []
        for attack in attacks:
            report = report_generator.generate_report(attack)
            reports.append(report)
        
        logger.info("=== DEMO COMPLETE ===")
        
        return {
            "status": "success",
            "demo_complete": True,
            "summary": {
                "baseline_events": len(enriched_normal),
                "attack_events": len(enriched_attack),
                "events_with_risk_quantified": len(event_analyses),
                "attacks_detected": len(attacks),
                "reports_generated": len(reports)
            },
            "all_events_risk": event_analyses,
            "highest_risk": {
                "event_type": highest_risk["event"]["event_type"],
                "anomaly_probability": f"{highest_risk['event']['anomaly_probability']*100:.1f}%",
                "annual_loss_expectancy": f"${highest_risk['event']['annual_loss_expectancy']:,.0f}",
                "priority": highest_risk["event"]["priority"],
                "strategy": highest_risk["event"]["strategy"],
                "timeline": highest_risk["treatment"].get("implementation_timeline"),
                "controls": highest_risk["treatment"].get("recommended_controls", [])[:3]
            } if highest_risk else None
        }
    
    except Exception as e:
        logger.error(f"Demo error: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analyze")
async def analyze_with_risk_engine(normal_count: int = 30):
    """Full risk analysis pipeline"""
    try:
        logger.info("=== RISK ANALYSIS START ===")
        
        # Baseline
        normal_events = mock_wazuh.generate_events(count=normal_count)
        enriched_normal = []
        for event in normal_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_normal.append(enriched_dict)
        
        baseline = baseline_model.build_user_baseline("analysis_user", enriched_normal)
        
        # Attack
        attack_events = mock_wazuh.generate_attack_scenario()
        enriched_attack = []
        for event in attack_events:
            enriched = await enrichment_service.enrich_event(event)
            enriched_dict = {
                **enriched.event.dict(),
                "threat_intel": {k: v.dict() for k, v in enriched.threat_intel.items()}
            }
            enriched_attack.append(enriched_dict)
        
        # Risk calculation per event
        event_risks = []
        for event in enriched_attack:
            anomaly_prob, anomaly_details = anomaly_probability.calculate_probability(event, baseline)
            chi2_prob, chi2_details = chi_square_tests.test_process_distribution([event], baseline)
            risk_metrics = monte_carlo_fair.calculate_risk(event, anomaly_prob)
            treatment = risk_treatment.recommend_treatment(risk_metrics, event)
            
            event_risks.append({
                "event": event.get("event_type"),
                "user": event.get("user"),
                "anomaly_probability": float(anomaly_prob),
                "annual_loss_expectancy": float(risk_metrics.get("annual_loss_expectancy", 0)),
                "value_at_risk_95": float(risk_metrics.get("value_at_risk_95", 0)),
                "priority": treatment.get("priority"),
                "strategy": treatment.get("strategy"),
                "recommended_controls": treatment.get("recommended_controls", [])[:2]
            })
        
        attacks = kill_chain_correlator.correlate_events(enriched_attack)
        reports = [report_generator.generate_report(a) for a in attacks]
        hypotheses = []
        for a in attacks:
            hypotheses.extend(hypothesis_generator.generate_hypotheses_from_attack(a))
        
        logger.info("=== ANALYSIS COMPLETE ===")
        
        return {
            "status": "success",
            "summary": {
                "total_events": len(enriched_attack),
                "attacks_found": len(attacks),
                "reports_generated": len(reports),
                "hypotheses_generated": len(hypotheses)
            },
            "event_risks": event_risks,
            "attacks": len(attacks),
            "reports": len(reports)
        }
    
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
