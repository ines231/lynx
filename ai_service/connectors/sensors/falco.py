"""
Falco (https://falco.org) -> SecurityEvent.

Falco writes one JSON document per alert when ``json_output: true`` and
``file_output`` are enabled. A document looks like::

    {"time": "2026-10-15T20:12:44.123456789Z", "rule": "Read sensitive file untrusted",
     "priority": "Warning", "hostname": "lab-vm", "source": "syscall",
     "tags": ["filesystem", "mitre_credential_access", "T1555"],
     "output": "...",
     "output_fields": {"proc.name": "cat", "proc.cmdline": "cat /etc/shadow",
                       "user.name": "root", "fd.name": "/etc/shadow"}}
"""

import re
from typing import Any, Dict, Optional

from config.settings import settings
from ai_service.connectors.models.event import SecurityEvent
from ai_service.connectors.sensors.common import (
    basename, event_type_from_techniques, parse_time, port, technique_ids,
)

PRIORITY_SEVERITY = {
    "emergency": "critical", "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium",
    "notice": "low", "informational": "low", "info": "low", "debug": "low",
}

# Used when a rule carries no ATT&CK id: keywords of the rule name.
RULE_KEYWORDS = [
    (("scan", "nmap", "recon"), "port_scan"),
    (("privilege", "setuid", "sudo", "escalat", "capabilit"), "privilege_escalation"),
    (("cron", "scheduled", "systemd", "service"), "scheduled_task"),
    (("ssh", "lateral", "remote"), "lateral_movement"),
    (("password", "credential", "shadow", "secret", "key"), "credential_use"),
    (("netcat", "exfil", "upload", "outbound", "curl", "wget"), "data_transfer"),
    (("sensitive file", "read", "write", "modif", "delet", "history", "log"), "file_access"),
    (("shell", "launch", "spawn", "execut", "process"), "process_execution"),
    (("connect", "network", "dns", "inbound"), "network_connection"),
]

NETWORK_TUPLE = re.compile(r"^(?P<cip>[^:>\s]+):(?P<cport>\d+)->(?P<sip>[^:>\s]+):(?P<sport>\d+)$")


def _event_type(ids, rule_name: str) -> str:
    by_technique = event_type_from_techniques(ids)
    if by_technique:
        return by_technique
    lowered = rule_name.lower()
    for keywords, event_type in RULE_KEYWORDS:
        if any(k in lowered for k in keywords):
            return event_type
    return "security_alert"


def falco_to_event(doc: Dict[str, Any]) -> Optional[SecurityEvent]:
    if not isinstance(doc, dict) or "rule" not in doc:
        return None
    timestamp = parse_time(doc.get("time"))
    if timestamp is None:
        return None

    fields = doc.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}
    tags = [str(t) for t in (doc.get("tags") or [])]
    ids = technique_ids(tags)
    rule_name = str(doc.get("rule") or "")

    source_ip, dest_ip, source_port, dest_port = settings.sensor_default_ip, None, None, None
    file_path = None
    fd_name = str(fields.get("fd.name") or "")
    network = NETWORK_TUPLE.match(fd_name)
    if network:
        source_ip, source_port = network["cip"], port(network["cport"])
        dest_ip, dest_port = network["sip"], port(network["sport"])
    elif fd_name.startswith("/"):
        file_path = fd_name
    source_ip = str(fields.get("fd.cip") or source_ip)
    dest_ip = fields.get("fd.sip") or dest_ip

    cmdline = fields.get("proc.cmdline")
    try:
        return SecurityEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=port(fields.get("fd.sport")) or dest_port,
            event_type=_event_type(ids, rule_name),
            user=fields.get("user.name"),
            hostname=doc.get("hostname"),
            process_name=basename(fields.get("proc.exepath")) or fields.get("proc.name"),
            command_line=str(cmdline) if cmdline else None,
            file_path=file_path,
            rule_description=rule_name,
            severity=PRIORITY_SEVERITY.get(str(doc.get("priority", "")).lower(), "low"),
            metadata={"source": "falco", "mitre_ids": ids, "tags": tags},
        )
    except Exception:       # an exotic document must never break an analysis
        return None
