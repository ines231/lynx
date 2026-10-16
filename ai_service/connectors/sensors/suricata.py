"""
Suricata (https://suricata.io) ``eve.json`` -> SecurityEvent.

Only ``"event_type": "alert"`` documents are used::

    {"timestamp": "2026-10-15T20:12:44.123456+0100", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 51234, "dest_ip": "10.0.0.9", "dest_port": 22,
     "proto": "TCP",
     "alert": {"signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
               "category": "Web Application Attack", "severity": 2,
               "metadata": {"mitre_technique_id": ["T1595"]}}}
"""

import socket
from typing import Any, Dict, Optional

from ai_service.connectors.models.event import SecurityEvent
from ai_service.connectors.sensors.common import (
    event_type_from_techniques, parse_time, port, technique_ids,
)

SEVERITY = {1: "high", 2: "medium", 3: "low"}      # Suricata: 1 is the most severe

SIGNATURE_KEYWORDS = [
    (("scan", "nmap", "masscan", "recon", "sweep"), "port_scan"),
    (("brute", "login attempt", "credential", "password"), "credential_use"),
    (("exploit", "shellcode", "overflow", "privilege"), "privilege_escalation"),
    (("dns",), "dns_query"),
    (("exfil", "upload", "data leak", "outbound"), "data_transfer"),
]


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def suricata_to_event(doc: Dict[str, Any]) -> Optional[SecurityEvent]:
    if not isinstance(doc, dict) or doc.get("event_type") != "alert":
        return None
    timestamp = parse_time(doc.get("timestamp"))
    alert = doc.get("alert")
    if timestamp is None or not isinstance(alert, dict) or not doc.get("src_ip"):
        return None

    signature = str(alert.get("signature") or "")
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    ids = technique_ids(_as_list(metadata.get("mitre_technique_id")))

    event_type = event_type_from_techniques(ids)
    if event_type is None:
        lowered = f"{signature} {alert.get('category', '')}".lower()
        event_type = next(
            (t for keywords, t in SIGNATURE_KEYWORDS if any(k in lowered for k in keywords)),
            "network_connection",
        )

    try:
        return SecurityEvent(
            timestamp=timestamp,
            source_ip=str(doc["src_ip"]),
            destination_ip=doc.get("dest_ip"),
            source_port=port(doc.get("src_port")),
            destination_port=port(doc.get("dest_port")),
            event_type=event_type,
            hostname=doc.get("host") or socket.gethostname(),   # eve.json has no host: use this machine
            rule_id=alert.get("signature_id") if isinstance(alert.get("signature_id"), int) else None,
            rule_description=signature,
            severity=SEVERITY.get(alert.get("severity"), "low"),
            metadata={"source": "suricata", "mitre_ids": ids,
                      "category": alert.get("category"), "proto": doc.get("proto")},
        )
    except Exception:
        return None
