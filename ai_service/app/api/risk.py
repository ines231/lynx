from fastapi import APIRouter, HTTPException, Response
from typing import Optional
import logging
import traceback

from ai_service.risk.baseline_model import baseline_model
from ai_service.risk.anomaly_probability import anomaly_probability
from ai_service.risk.chi_square_tests import chi_square_tests
from ai_service.risk.monte_carlo_fair import monte_carlo_fair
from ai_service.risk.risk_treatment import risk_treatment
from ai_service.risk.currency import get_display_currency
from ai_service.risk.pipeline import (
    NORMAL_EVENT_TYPES,
    analysis_store,
    enriched_event_to_dict as _enriched_event_to_dict,
    public_view,
    run_analysis,
)

from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh
from ai_service.enrichment.enrichment_service import enrichment_service
from ai_service.correlation.kill_chain import kill_chain_correlator
from ai_service.reports.investigation_report import report_generator
from ai_service.reports.pdf_report import build_risk_report
from ai_service.hypotheses.hypothesis_generator import hypothesis_generator


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/risk",
    tags=["risk"]
)


def _format_amount(amount, currency):
    """Format an amount already in the display currency, e.g. '17 497,32 DT'."""
    value = float(amount)
    text = f"{value:,.2f}".replace(",", "\u00a0").replace(".", ",")
    return f"{text}\u00a0{currency.symbol}"


@router.get("/")
async def get_risk_info():
    return {
        "service": "Probabilistic FAIR Risk Engine",
        "version": "0.1.0",
        "endpoints": [
            "GET /api/risk/demo - Full risk engine demo",
            "GET /api/risk/analyze - Complete risk analysis",
            "GET /api/risk/report.pdf - Structured PDF report",
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

        currency = get_display_currency()

        # =========================================================
        # STEP 1 - BUILD BASELINE
        # =========================================================

        logger.info(
            "Step 1: Building baseline on 30 normal events..."
        )

        normal_events = mock_wazuh.generate_events(
            count=30,
            event_types=NORMAL_EVENT_TYPES
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

                "annual_loss_expectancy": currency.convert(
                    risk_metrics.get("annual_loss_expectancy", 0)
                ),

                "value_at_risk_95": currency.convert(
                    risk_metrics.get("value_at_risk_95", 0)
                ),

                "value_at_risk_99": currency.convert(
                    risk_metrics.get("value_at_risk_99", 0)
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

            "currency": currency.to_dict(),

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
                        _format_amount(highest_risk['event']['annual_loss_expectancy'], currency)
                    ),

                    "value_at_risk_95": (
                        _format_amount(highest_risk['event']['value_at_risk_95'], currency)
                    ),

                    "value_at_risk_99": (
                        _format_amount(highest_risk['event']['value_at_risk_99'], currency)
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
    normal_count: int = 30,
    seed: Optional[int] = None
):
    """
    Full risk analysis pipeline.

    `seed` makes the mock data (and therefore every figure) reproducible.
    The response carries an `analysis_id`: pass it to `/report.pdf` to download
    the report of exactly this analysis.
    """

    try:
        logger.info("=== RISK ANALYSIS START ===")

        analysis = await run_analysis(normal_count=normal_count, seed=seed)
        analysis_store.put(analysis)

        logger.info("=== ANALYSIS COMPLETE ===")

        return public_view(analysis)

    except Exception as e:

        logger.error(f"Analysis error: {e}")
        logger.error(traceback.format_exc())

        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report.pdf")
async def download_risk_report(
    analysis_id: Optional[str] = None,
    normal_count: int = 30,
    seed: Optional[int] = None
):
    """
    Structured PDF report.

    * with `analysis_id` (returned by `/analyze`): the PDF contains exactly the
      figures the dashboard is showing; 410 if that analysis is no longer in
      memory (server restarted or too many newer analyses);
    * without it: a fresh analysis is run (use `seed` to make it reproducible).
    """

    try:
        if analysis_id:
            analysis = analysis_store.get(analysis_id)

            if analysis is None:
                raise HTTPException(
                    status_code=410,
                    detail=(
                        "Analyse expirée (serveur redémarré ou analyse "
                        "trop ancienne) : relancez l'analyse."
                    )
                )
        else:
            analysis = await run_analysis(
                normal_count=normal_count, seed=seed
            )
            analysis_store.put(analysis)

        pdf_bytes = build_risk_report(analysis)

        filename = f"lynx-rapport-{analysis['analysis_id']}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    except HTTPException:
        raise

    except Exception as e:

        logger.error(f"Report error: {e}")
        logger.error(traceback.format_exc())

        raise HTTPException(status_code=500, detail=str(e))


# Singleton router is imported by the FastAPI application.
