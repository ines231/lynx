"""Shared helpers for the LYNX risk engine.

Keeping these in one place guarantees that the baseline, the anomaly model,
the FAIR simulation and the treatment engine all interpret an event the same
way.
"""

import ipaddress
import re
from typing import Any, Optional

# Substring stems on purpose: "financ" matches both "finance" and "financial".
# "hr" is only accepted as a whole path/word segment, otherwise it would match
# harmless paths such as "C:\\Program Files\\Chrome" or "shared".
_SENSITIVE_PATH = re.compile(
    r"financ|confidential|secret|salar|password"
    r"|(?:^|[\\/_.\- ])hr(?:[\\/_.\- ]|$)",
    re.IGNORECASE,
)

# Raw Wazuh/mock event types -> FAIR / kill-chain category used for TEF and PLM.
FAIR_CATEGORY_ALIASES = {
    "port_scan": "reconnaissance",
    "network_scan": "reconnaissance",
    "dns_query": "reconnaissance",
    "service_installation": "persistence",
    "registry_modification": "persistence",
    "scheduled_task": "persistence",
}


def get_value(event: Any, key: str, default=None):
    """Read a field from a dict or from a Pydantic/model object."""
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def is_sensitive_path(path: Optional[str]) -> bool:
    """True when a file path looks like finance / HR / confidential data."""
    return bool(path) and bool(_SENSITIVE_PATH.search(str(path)))


# Internal address space: RFC1918 + loopback + link-local (+ IPv6 equivalents).
# ipaddress.is_private is NOT used on purpose: it also returns True for the
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which the
# mock connector uses as "external" addresses.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_private_ip(ip: Optional[str]) -> bool:
    """True for internal addresses (matched on the real network ranges).

    ``startswith("172.")`` is wrong: only 172.16.0.0/12 is private.
    """
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(
        address.version == network.version and address in network
        for network in _INTERNAL_NETWORKS
    )


def fair_category(event: Any) -> str:
    """Map an event to the category used by the FAIR parameters.

    * port_scan / dns_query -> reconnaissance
    * service_installation / registry_modification -> persistence
    * file_access towards a public IP -> exfiltration
    * anything else keeps its own (lower-cased) event type
    """
    event_type = str(get_value(event, "event_type", "") or "").lower()

    if event_type == "file_access":
        destination_ip = get_value(event, "destination_ip", None)
        if destination_ip and not is_private_ip(destination_ip):
            return "exfiltration"

    return FAIR_CATEGORY_ALIASES.get(event_type, event_type)
