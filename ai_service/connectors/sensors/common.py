"""Shared helpers of the sensor adapters (Falco, Suricata)."""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ATT&CK technique (prefix) -> event type of the platform.
TECHNIQUE_EVENT_TYPES = [
    (("T1046", "T1595", "T1018", "T1135"), "port_scan"),
    (("T1068", "T1548", "T1134", "T1611"), "privilege_escalation"),
    (("T1055",), "code_injection"),
    (("T1053",), "scheduled_task"),
    (("T1543",), "service_installation"),
    (("T1547", "T1112", "T1546", "T1037"), "registry_modification"),
    (("T1021", "T1570", "T1550", "T1563", "T1210"), "lateral_movement"),
    (("T1110", "T1078", "T1003", "T1558", "T1552", "T1555"), "credential_use"),
    (("T1041", "T1048", "T1567", "T1537", "T1020", "T1030", "T1105"), "data_transfer"),
    (("T1560",), "archive_creation"),
    (("T1005", "T1039", "T1025", "T1083", "T1222", "T1070", "T1565"), "file_access"),
    (("T1059", "T1204", "T1106"), "process_execution"),
]

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def event_type_from_techniques(ids: List[str]) -> Optional[str]:
    for prefixes, event_type in TECHNIQUE_EVENT_TYPES:
        if any(i.upper().startswith(prefixes) for i in ids):
            return event_type
    return None


def technique_ids(values) -> List[str]:
    """Keep the strings that are ATT&CK technique ids (T1059, T1053.003)."""
    found: List[str] = []
    for value in values or []:
        text = str(value).strip().upper()
        if TECHNIQUE_ID.match(text) and text not in found:
            found.append(text)
    return found


def parse_time(raw: Any) -> Optional[datetime]:
    """Naive UTC datetime. Handles 'Z', '+0100' and nanosecond fractions."""
    if not raw:
        return None
    text = str(raw).strip().replace("Z", "+00:00")
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)          # +0100 -> +01:00
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)                    # 9 -> 6 fractional digits
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def port(value) -> Optional[int]:
    try:
        number = int(value)
        return number if 0 < number < 65536 else None
    except (TypeError, ValueError):
        return None


def basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return re.split(r"[\\/]", str(path).rstrip("\\/"))[-1] or None


def read_json_lines(path: str, max_mb: int = 64) -> Iterator[Dict[str, Any]]:
    """
    Yield the JSON documents of a log file (one per line). Only the last
    ``max_mb`` megabytes are read, and damaged lines are skipped: a sensor that
    is still writing must never break an analysis.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        if size > max_mb * 1024 * 1024:
            handle.seek(size - max_mb * 1024 * 1024)
            handle.readline()                      # drop the partial first line
        for raw in handle:
            # NUL bytes appear in front of a line when the file was truncated while the
            # sensor kept writing (log rotation): the JSON itself is intact.
            raw = raw.strip(b"\x00 \t\r\n")
            if not raw.startswith(b"{"):
                continue
            try:
                document = json.loads(raw)
            except ValueError:
                continue
            if isinstance(document, dict):
                yield document
