from fastapi import APIRouter, HTTPException
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

router = APIRouter(
    prefix="/api/risk",
    tags=["risk"]
)


def _model_to_dict(model):
    """
    Convert Pydantic v1/v2 models to dictionaries.
    """
    if hasattr(model, "model_dump"):
        return model.model_dump()

    if hasattr(model, "dict"):
        return model.dict()

    if isinstance(model, dict):
        return model

    return {}


def _enriched_event_to_dict(enriched):
    """
    Convert an EnrichedEvent object into a normal dictionary.
    """

    event_dict = _model_to_dict(enriched.event)

    threat_intel_dict = {}

    for key, value in enriched.threat_intel.items():
        threat_intel_dict[key] = _model_to_dict(value)

    event_dict["threat_intel"] = threat_intel_dict

    return event_dict


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
    """
    Complete risk engine demo.

    Pipeline:

    Mock Wazuh
        ↓
    Enrichment
        ↓
    Baseline
        ↓
    Anomaly Detection
        ↓
    FAIR / Monte Carlo
        ↓
    Risk Treatment
        ↓
    Kill Chain
        ↓
    Investigation Reports
    """

    try:
        logger.info("=== RISK ENGINE DEMO START ===")

        # =========================================================
        # STEP 1 - BUILD BASELINE
        # =========================================================

        logger.info(
            "Step 1: Building baseline on 30 normal events..."
        )

        normal_events = mock_wazuh.generate_events(
            count=30
        )

        enriched_normal = []

        for event in normal_events:

            enriched = await enrichment_service.enrich_event(
                event
            )

            enriched_dict = _enriched_event_to_dict(
                enriched
            )

            enriched_normal.append(
                enriched_dict
            )

        baseline = baseline_model.build_user_baseline(
            "demo_user",
            enriched_normal
        )

        # =========================================================
        # STEP 2 - GENERATE ATTACK SCENARIO
        # =========================================================

        logger.info(
            "Step 2: Generating attack scenario..."
        )

        attack_events = (
            mock_wazuh.generate_attack_scenario()
        )

        enriched_attack = []

        for event in attack_events:

            enriched = await enrichment_service.enrich_event(
                event
            )

            enriched_dict = _enriched_event_to_dict(
                enriched
            )

            enriched_attack.append(
                enriched_dict
            )

        # =========================================================
        # STEP 3 - RISK ANALYSIS
        # =========================================================

        logger.info(
            "Step 3: Calculating risk for each event..."
        )

        event_analyses = []

        highest_risk = None

        for event in enriched_attack:

            # Anomaly detection
            anomaly_prob, anomaly_details = (
                anomaly_probability.calculate_probability(
                    event,
                    baseline
                )
            )

            # FAIR / Monte Carlo
            risk_metrics = (
                monte_carlo_fair.calculate_risk(
                    event,
                    anomaly_prob
                )
            )

            # Risk treatment
            treatment = (
                risk_treatment.recommend_treatment(
                    risk_metrics,
                    event
                )
            )

            analysis = {
                "event_type": event.get(
                    "event_type"
                ),

                "anomaly_probability": float(
                    anomaly_prob
                ),

                "annual_loss_expectancy": float(
                    risk_metrics.get(
                        "annual_loss_expectancy",
                        0
                    )
                ),

                "value_at_risk_95": float(
                    risk_metrics.get(
                        "value_at_risk_95",
                        0
                    )
                ),

                "value_at_risk_99": float(
                    risk_metrics.get(
                        "value_at_risk_99",
                        0
                    )
                ),

                "priority": treatment.get(
                    "priority"
                ),

                "strategy": treatment.get(
                    "treatment_strategy"
                )
            }

            event_analyses.append(
                analysis
            )

            ale = risk_metrics.get(
                "annual_loss_expectancy",
                0
            )

            if (
                highest_risk is None
                or ale > highest_risk["ale"]
            ):

                highest_risk = {
                    "event": analysis,
                    "ale": ale,
                    "treatment": treatment
                }

        # =========================================================
        # STEP 4 - KILL CHAIN CORRELATION
        # =========================================================

        logger.info(
            "Step 4: Correlating kill chain..."
        )

        attacks = (
            kill_chain_correlator.correlate_events(
                enriched_attack
            )
        )

        # =========================================================
        # STEP 5 - INVESTIGATION REPORTS
        # =========================================================

        logger.info(
            "Step 5: Generating investigation reports..."
        )

        reports = []

        for attack in attacks:

            report = (
                report_generator.generate_report(
                    attack
                )
            )

            reports.append(
                report
            )

        logger.info(
            "=== DEMO COMPLETE ==="
        )

        # =========================================================
        # RESPONSE
        # =========================================================

        return {
            "status": "success",
            "demo_complete": True,

            "summary": {
                "baseline_events": len(
                    enriched_normal
                ),

                "attack_events": len(
                    enriched_attack
                ),

                "events_with_risk_quantified": len(
                    event_analyses
                ),

                "attacks_detected": len(
                    attacks
                ),

                "reports_generated": len(
                    reports
                )
            },

            "all_events_risk": event_analyses,

            "highest_risk": (
                {
                    "event_type": highest_risk[
                        "event"
                    ]["event_type"],

                    "anomaly_probability": (
                        f"{highest_risk['event']['anomaly_probability'] * 100:.1f}%"
                    ),

                    "annual_loss_expectancy": (
                        f"${highest_risk['event']['annual_loss_expectancy']:,.2f}"
                    ),

                    "value_at_risk_95": (
                        f"${highest_risk['event']['value_at_risk_95']:,.2f}"
                    ),

                    "value_at_risk_99": (
                        f"${highest_risk['event']['value_at_risk_99']:,.2f}"
                    ),

                    "priority": highest_risk[
                        "event"
                    ]["priority"],

                    "strategy": highest_risk[
                        "event"
                    ]["strategy"],

                    "timeline": highest_risk[
                        "treatment"
                    ].get(
                        "implementation_timeline"
                    ),

                    "controls": highest_risk[
                        "treatment"
                    ].get(
                        "recommended_controls",
                        []
                    )[:3]
                }

                if highest_risk
                else None
            )
        }

    except Exception as e:

        logger.error(
            f"Demo error: {e}"
        )

        logger.error(
            traceback.format_exc()
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@router.get("/analyze")
async def analyze_with_risk_engine(
    normal_count: int = 30
):
    """
    Full risk analysis pipeline.
    """

    try:

        logger.info(
            "=== RISK ANALYSIS START ==="
        )

        # =========================================================
        # STEP 1 - BASELINE
        # =========================================================

        normal_events = (
            mock_wazuh.generate_events(
                count=normal_count
            )
        )

        enriched_normal = []

        for event in normal_events:

            enriched = (
                await enrichment_service.enrich_event(
                    event
                )
            )

            enriched_dict = (
                _enriched_event_to_dict(
                    enriched
                )
            )

            enriched_normal.append(
                enriched_dict
            )

        baseline = (
            baseline_model.build_user_baseline(
                "analysis_user",
                enriched_normal
            )
        )

        # =========================================================
        # STEP 2 - ATTACK SCENARIO
        # =========================================================

        attack_events = (
            mock_wazuh.generate_attack_scenario()
        )

        enriched_attack = []

        for event in attack_events:

            enriched = (
                await enrichment_service.enrich_event(
                    event
                )
            )

            enriched_dict = (
                _enriched_event_to_dict(
                    enriched
                )
            )

            enriched_attack.append(
                enriched_dict
            )

        # =========================================================
        # STEP 3 - RISK CALCULATION
        # =========================================================

        # Chi-square is a distribution test, so it must be computed
        # on the complete attack window rather than on one event.
        chi2_prob, chi2_details = (
            chi_square_tests.test_event_type_distribution(
                enriched_attack,
                baseline
            )
        )

        event_risks = []

        for event in enriched_attack:

            anomaly_prob, anomaly_details = (
                anomaly_probability.calculate_probability(
                    event,
                    baseline
                )
            )

            # Chi-square describes the statistical deviation of the
            # complete attack distribution. It is therefore shared as
            # scenario context across the event-level risk feed.

            # FAIR
            risk_metrics = (
                monte_carlo_fair.calculate_risk(
                    event,
                    anomaly_prob
                )
            )

            # Treatment
            treatment = (
                risk_treatment.recommend_treatment(
                    risk_metrics,
                    event
                )
            )

            event_risks.append(
                {
                    "event": event.get(
                        "event_type"
                    ),

                    "user": event.get(
                        "user"
                    ),

                    "anomaly_probability": float(
                        anomaly_prob
                    ),

                    "chi_square_probability": float(
                        chi2_prob
                    ),

                    "annual_loss_expectancy": float(
                        risk_metrics.get(
                            "annual_loss_expectancy",
                            0
                        )
                    ),

                    "value_at_risk_95": float(
                        risk_metrics.get(
                            "value_at_risk_95",
                            0
                        )
                    ),

                    "value_at_risk_99": float(
                        risk_metrics.get(
                            "value_at_risk_99",
                            0
                        )
                    ),

                    "priority": treatment.get(
                        "priority"
                    ),

                    "strategy": treatment.get(
                        "treatment_strategy"
                    ),

                    "recommended_controls": (
                        treatment.get(
                            "recommended_controls",
                            []
                        )[:2]
                    )
                }
            )

        # =========================================================
        # STEP 4 - KILL CHAIN
        # =========================================================

        attacks = (
            kill_chain_correlator.correlate_events(
                enriched_attack
            )
        )

        # =========================================================
        # STEP 5 - REPORTS
        # =========================================================

        reports = []

        for attack in attacks:

            reports.append(
                report_generator.generate_report(
                    attack
                )
            )

        # =========================================================
        # STEP 6 - HYPOTHESES
        # =========================================================

        hypotheses = []

        for attack in attacks:

            hypotheses.extend(
                hypothesis_generator.generate_hypotheses_from_attack(
                    attack
                )
            )

        logger.info(
            "=== ANALYSIS COMPLETE ==="
        )

        return {
            "status": "success",

            "summary": {
                "total_events": len(
                    enriched_attack
                ),

                "attacks_found": len(
                    attacks
                ),

                "reports_generated": len(
                    reports
                ),

                "hypotheses_generated": len(
                    hypotheses
                )
            },

            "event_risks": event_risks,

            "attacks": len(
                attacks
            ),

            "reports": len(
                reports
            )
        }

    except Exception as e:

        logger.error(
            f"Analysis error: {e}"
        )

        logger.error(
            traceback.format_exc()
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# Singleton router is imported by the FastAPI application.