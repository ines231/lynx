"""
Risk-analysis pipeline shared by the HTTP API and the PDF report.

Keeping the pipeline outside the FastAPI router means the exact same analysis
can feed the dashboard (``GET /api/risk/analyze``) and the downloadable report
(``GET /api/risk/report.pdf``), and can be unit-tested without a web server.
"""

import logging
import random
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ai_service.risk.baseline_model import baseline_model
from ai_service.risk.anomaly_probability import anomaly_probability
from ai_service.risk.chi_square_tests import chi_square_tests
from ai_service.risk.monte_carlo_fair import monte_carlo_fair
from ai_service.risk.risk_treatment import risk_treatment
from ai_service.risk.common import fair_category
from ai_service.risk.currency import get_display_currency
from config.settings import settings
from ai_service.mitre.knowledge_base import mitre_kb

from ai_service.connectors.sources import NORMAL_EVENT_TYPES, get_source  # noqa: F401
from ai_service.enrichment.enrichment_service import enrichment_service
from ai_service.correlation.kill_chain import kill_chain_correlator
from ai_service.reports.investigation_report import report_generator
from ai_service.hypotheses.hypothesis_generator import hypothesis_generator

logger = logging.getLogger(__name__)

def model_to_dict(model: Any) -> Dict[str, Any]:
    """Convert Pydantic v1/v2 models to dictionaries."""
    if hasattr(model, "model_dump"):
        return model.model_dump()

    if hasattr(model, "dict"):
        return model.dict()

    if isinstance(model, dict):
        return model

    return {}


def enriched_event_to_dict(enriched: Any) -> Dict[str, Any]:
    """Convert an EnrichedEvent object into a normal dictionary."""
    event_dict = model_to_dict(enriched.event)
    event_dict["threat_intel"] = {
        key: model_to_dict(value) for key, value in enriched.threat_intel.items()
    }
    return event_dict


async def _enrich_all(events) -> list:
    enriched_events = []
    for event in events:
        enriched = await enrichment_service.enrich_event(event)
        enriched_events.append(enriched_event_to_dict(enriched))
    return enriched_events


def _reputation_view(event) -> Dict[str, Any]:
    """Compact IP reputation of one event (score, country, provider) for the UI and the PDF."""
    out: Dict[str, Any] = {}
    intel = event.get("threat_intel") or {}
    for key in ("source_ip", "destination_ip"):
        item = intel.get(key)
        if not item:
            continue
        details = item.get("details") or {}
        out[key] = {
            "ip": item.get("indicator"),
            "score": float(item.get("reputation_score", 0)),
            "malicious": bool(item.get("is_malicious")),
            "source": item.get("source"),
            "country": details.get("country"),
            "isp": details.get("isp"),
            "reports": details.get("reports"),
        }
    return out


def _loss_histogram_view(event, index, risk_metrics, currency) -> Dict[str, Any]:
    """Loss distribution of one event, amounts converted to the display currency."""
    hist = risk_metrics.get("loss_histogram") or {}
    return {
        "_ale_usd": risk_metrics.get("annual_loss_expectancy", 0),
        "event": event.get("event_type"),
        "event_index": index,
        "edges": [currency.convert(e) for e in hist.get("edges", [])],
        "counts": list(hist.get("counts", [])),
        "loss_years": hist.get("loss_years", 0),
        "total_years": hist.get("total_years", 0),
        "annual_loss_expectancy": currency.convert(
            risk_metrics.get("annual_loss_expectancy", 0)
        ),
        "value_at_risk_95": currency.convert(risk_metrics.get("value_at_risk_95", 0)),
        "value_at_risk_99": currency.convert(risk_metrics.get("value_at_risk_99", 0)),
        "expected_shortfall_95": currency.convert(
            risk_metrics.get("expected_shortfall_95", 0)
        ),
    }


def _strip_private(view):
    return {k: v for k, v in view.items() if not k.startswith("_")} if view else None


async def run_analysis(
    normal_count: int = 30,
    seed: Optional[int] = None,
    currency_code: Optional[str] = None,
    source: Optional[str] = None,
    window_hours: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Run the full pipeline and return everything the API and the report need.

    Pipeline: baseline on normal events -> attack scenario -> chi-square on the
    whole attack window -> per-event anomaly probability / FAIR Monte Carlo /
    treatment -> kill chain -> investigation reports -> hunting hypotheses.

    `seed` makes the mock data (and therefore every figure) reproducible.
    """

    if seed is not None:
        random.seed(seed)

    # The engine prices losses in USD; every amount that leaves the pipeline
    # is converted once into the display currency (TND by default).
    currency = get_display_currency(currency_code)

    # ---- 1. baseline ---------------------------------------------------
    event_source = get_source(source)
    # same order as always (baseline, then scenario): with the mock source a seed
    # must keep giving the same figures.
    normal_events = await event_source.baseline_events(normal_count, window_hours)
    enriched_normal = await _enrich_all(normal_events)
    baseline = baseline_model.build_user_baseline("analysis_user", enriched_normal)

    # ---- 2. attack scenario -------------------------------------------
    enriched_attack = await _enrich_all(await event_source.attack_events(window_hours))

    # ---- 3. risk -------------------------------------------------------
    # Chi-square is a distribution test, so it is computed on the complete
    # attack window rather than on one event.
    # chi2_prob = 1 - p_value: evidence that the window deviates from the
    # baseline (close to 1 = very unusual, close to 0 = normal). It describes
    # the whole scenario and is therefore shared by every event of the feed.
    chi2_prob, chi2_details = chi_square_tests.test_event_type_distribution(
        enriched_attack, baseline
    )

    event_risks = []
    event_details = []
    loss_histogram = None  # of the event with the highest ALE

    # Anomaly probabilities first: in "observed" mode the frequency of each category
    # (sum of the probabilities of its events) is needed before any event is priced.
    anomaly_probs = [
        anomaly_probability.calculate_probability(event, baseline)[0]
        for event in enriched_attack
    ]
    tef_mode = str(settings.tef_mode or "auto").lower()
    use_observed = tef_mode == "observed" or (
        tef_mode == "auto" and bool(event_source.describe().get("is_real"))
    )
    observation_days = max(
        float(settings.tef_observation_days), float(window_hours or 0) / 24
    )
    category_load: Dict[str, float] = {}
    for event, prob in zip(enriched_attack, anomaly_probs):
        category = fair_category(event)
        category_load[category] = category_load.get(category, 0.0) + prob

    for index, event in enumerate(enriched_attack):
        anomaly_prob = anomaly_probs[index]
        observed_rate = (
            category_load[fair_category(event)] * 365.0 / observation_days
            if use_observed else None
        )
        risk_metrics = monte_carlo_fair.calculate_risk(
            event, anomaly_prob, observed_rate
        )
        if loss_histogram is None or risk_metrics.get(
            "annual_loss_expectancy", 0
        ) > loss_histogram["_ale_usd"]:
            loss_histogram = _loss_histogram_view(
                event, index, risk_metrics, currency
            )
        treatment = risk_treatment.recommend_treatment(risk_metrics, event)

        controls = treatment.get("recommended_controls", [])

        event_risks.append(
            {
                "event": event.get("event_type"),
                "stage": kill_chain_correlator.classify_stage(event),
                "user": event.get("user"),
                "anomaly_probability": float(anomaly_prob),
                "chi_square_probability": float(chi2_prob),
                "annual_loss_expectancy": currency.convert(
                    risk_metrics.get("annual_loss_expectancy", 0)
                ),
                "value_at_risk_95": currency.convert(
                    risk_metrics.get("value_at_risk_95", 0)
                ),
                "value_at_risk_99": currency.convert(
                    risk_metrics.get("value_at_risk_99", 0)
                ),
                "priority": treatment.get("priority"),
                "strategy": treatment.get("treatment_strategy"),
                "recommended_controls": controls[:2],
            }
        )

        # Richer, report-only view of the same event (not sent by /analyze).
        event_details.append(
            {
                "timestamp": str(event.get("timestamp")),
                "hostname": event.get("hostname"),
                "reputation": _reputation_view(event),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "threat_event_frequency": float(
                    risk_metrics.get("threat_event_frequency", 0)
                ),
                "vulnerability": float(risk_metrics.get("vulnerability", 0)),
                "loss_event_frequency": float(
                    risk_metrics.get("loss_event_frequency", 0)
                ),
                "probable_loss_magnitude": currency.convert(
                    risk_metrics.get("probable_loss_magnitude", 0)
                ),
                "probability_of_loss": float(
                    risk_metrics.get("probability_of_loss", 0)
                ),
                "expected_shortfall_95": currency.convert(
                    risk_metrics.get("expected_shortfall_95", 0)
                ),
                "implementation_timeline": treatment.get("implementation_timeline"),
                "recommended_controls": list(controls[:5]),
                "target_ale": currency.convert(
                    (treatment.get("risk_metrics") or {}).get(
                        "target_annual_loss_expectancy", 0
                    )
                ),
                "risk_reduction_target": (treatment.get("risk_metrics") or {}).get(
                    "risk_reduction_target"
                ),
            }
        )

    # ---- 4. kill chain, reports, hypotheses ---------------------------
    attacks = kill_chain_correlator.correlate_events(enriched_attack)
    reports = [report_generator.generate_report(attack) for attack in attacks]

    hypotheses = []
    for attack in attacks:
        hypotheses.extend(
            hypothesis_generator.generate_hypotheses_from_attack(attack)
        )

    return {
        "analysis_id": uuid.uuid4().hex[:12],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parameters": {"normal_count": normal_count, "seed": seed},
        "data_source": event_source.describe(),
        "risk_model": {
            "tef_mode": "observed" if use_observed else "prior",
            "observation_days": observation_days if use_observed else None,
        },
        "currency": currency.to_dict(),
        "mitre": {
            "source": mitre_kb.source_label(),
            "official_data": mitre_kb.is_official,
            "attack_version": mitre_kb.status().get("attack_version"),
            "technique_count": mitre_kb.status().get("technique_count"),
        },
        "baseline": {
            "user": baseline.get("user"),
            "event_count": baseline.get("event_count"),
            "event_types": dict(baseline.get("event_types", {})),
            "severity_distribution": dict(
                baseline.get("severity_distribution", {})
            ),
        },
        "events": enriched_attack,
        "event_risks": event_risks,
        "event_details": event_details,
        "loss_histogram": _strip_private(loss_histogram),
        "chi_square": chi2_details,
        "attacks": attacks,
        "reports": reports,
        "hypotheses": hypotheses,
    }


def public_view(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """The JSON-safe payload returned by ``GET /api/risk/analyze``."""
    return {
        "status": "success",
        "analysis_id": analysis["analysis_id"],
        "generated_at": analysis["generated_at"],
        "parameters": analysis["parameters"],
        "data_source": analysis.get("data_source"),
        "risk_model": analysis.get("risk_model"),
        "currency": analysis["currency"],
        "mitre": analysis["mitre"],
        "summary": {
            "total_events": len(analysis["events"]),
            "attacks_found": len(analysis["attacks"]),
            "reports_generated": len(analysis["reports"]),
            "hypotheses_generated": len(analysis["hypotheses"]),
        },
        "baseline": analysis["baseline"],
        "event_risks": analysis["event_risks"],
        "event_details": analysis.get("event_details", []),
        "loss_histogram": analysis.get("loss_histogram"),
        "chi_square": analysis["chi_square"],
        "attacks": len(analysis["attacks"]),
        "reports": len(analysis["reports"]),
    }


class AnalysisStore:
    """
    Small in-memory store of the latest analyses, so that the PDF downloaded
    from the dashboard contains exactly the figures the analyst is looking at.
    It is bounded (oldest entries are dropped) and lost on restart.
    """

    def __init__(self, max_items: int = 32):
        self.max_items = max_items
        self._items: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    def put(self, analysis: Dict[str, Any]) -> str:
        analysis_id = analysis["analysis_id"]
        self._items[analysis_id] = analysis
        self._items.move_to_end(analysis_id)
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return analysis_id

    def get(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self._items.get(analysis_id)

    def __len__(self) -> int:
        return len(self._items)


analysis_store = AnalysisStore()
