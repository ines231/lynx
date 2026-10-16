"""
Operational priority for threat hunting: "what should I look at first, and why?".

It answers a different question from the FAIR figures (which estimate a yearly financial
exposure for management reporting). The score is a transparent sum of five signals,
0 to 100, and every event comes with the reasons that raised it.

    anomaly       35  how unusual the event is compared with the baseline
    category      30  how serious this kind of activity is (exfiltration > scan)
    sensor        15  severity reported by the sensor itself (Falco / Suricata / Wazuh)
    reputation    15  IP reputation (malicious flag, or the provider score)
    kill chain     5  how far along the attack chain the event sits

The weights and levels are expert-set assumptions, not learned values.
"""

from typing import Any, Dict, List

from ai_service.risk.common import fair_category, get_value
from config.settings import settings

WEIGHTS = {"anomaly": 35.0, "category": 30.0, "sensor": 15.0, "reputation": 15.0, "stage": 5.0}

CATEGORY_SEVERITY = {
    "exfiltration": 1.0,
    "privilege_escalation": 0.9,
    "lateral_movement": 0.85,
    "credential_access": 0.8,
    "persistence": 0.7,
    "exploitation": 0.7,
    "reconnaissance": 0.4,
}
DEFAULT_CATEGORY_SEVERITY = 0.25

SENSOR_SEVERITY = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25}

STAGES = ["reconnaissance", "exploitation", "persistence", "lateral_movement", "exfiltration"]

LEVELS = {
    "INVESTIGATE": "À investiguer maintenant",
    "MONITOR": "À surveiller",
    "NOISE": "Bruit probable",
}


def _reputation(event: Any) -> Dict[str, Any]:
    """Strongest reputation signal among the source and destination IPs."""
    intel = get_value(event, "threat_intel", {}) or {}
    best = {"value": 0.0, "malicious": False, "score": 0.0, "source": None}
    for key in ("source_ip", "destination_ip"):
        item = intel.get(key) if isinstance(intel, dict) else None
        if not isinstance(item, dict):
            continue
        malicious = bool(item.get("is_malicious"))
        score = float(item.get("reputation_score") or 0.0)
        value = 1.0 if malicious else min(max(score / 100.0, 0.0), 1.0)
        if value > best["value"]:
            best = {"value": value, "malicious": malicious, "score": score,
                    "source": item.get("source")}
    return best


def assess(event: Any, anomaly_prob: float, stage: str = "unknown") -> Dict[str, Any]:
    """Score one event. Returns the score (0-100), the level and the reasons."""
    category = fair_category(event)
    category_value = CATEGORY_SEVERITY.get(category, DEFAULT_CATEGORY_SEVERITY)

    severity = str(get_value(event, "severity", "low") or "low").lower()
    sensor_value = SENSOR_SEVERITY.get(severity, 0.25)

    reputation = _reputation(event)
    stage_value = STAGES.index(stage) / (len(STAGES) - 1) if stage in STAGES else 0.0
    p = min(max(float(anomaly_prob or 0.0), 0.0), 1.0)

    score = (
        WEIGHTS["anomaly"] * p
        + WEIGHTS["category"] * category_value
        + WEIGHTS["sensor"] * sensor_value
        + WEIGHTS["reputation"] * reputation["value"]
        + WEIGHTS["stage"] * stage_value
    )

    reasons: List[str] = []
    if p >= 0.5:
        reasons.append(f"Comportement inhabituel par rapport à la baseline (anomalie {p * 100:.0f} %)")
    if category_value >= 0.7:
        reasons.append(f"Catégorie de menace sérieuse : {category}")
    if severity in ("high", "critical"):
        reasons.append(f"Gravité « {severity} » signalée par le capteur")
    if reputation["malicious"]:
        reasons.append(f"IP signalée comme malveillante (score {reputation['score']:.0f}/100)")
    elif reputation["score"] >= 25:
        reasons.append(f"IP à réputation douteuse (score {reputation['score']:.0f}/100)")
    if stage_value >= 0.5:
        reasons.append(f"Étape avancée de la chaîne d'attaque : {stage}")
    if not reasons:
        reasons.append("Aucun signal fort : comportement proche de la baseline")

    level = ("INVESTIGATE" if score >= float(settings.hunt_investigate_from)
             else "MONITOR" if score >= float(settings.hunt_monitor_from) else "NOISE")
    return {
        "score": round(score, 1),
        "level": level,
        "label": LEVELS[level],
        "reasons": reasons,
    }
