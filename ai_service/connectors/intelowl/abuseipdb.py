"""
Real IP reputation from AbuseIPDB (https://www.abuseipdb.com, free key: 1 000 checks/day).

Only IP lookups are real. Domains, hashes and URLs stay simulated (mock connector), and
the result's ``source`` field says which is which. Rules:

* private / loopback / link-local addresses are never sent out (they are "local_network");
* each IP is cached (``ti_cache_hours``) and concurrent lookups of one IP share one call,
  so a run over hundreds of events costs a handful of requests;
* any failure (no network, bad key, quota) gives a NEUTRAL "unknown" result, never a
  random one: an outage must not invent malicious IPs. After a 401/403/429 the
  provider pauses for ``COOLDOWN_SECONDS`` instead of hammering the API.
"""

import asyncio
import ipaddress
import logging
import time
from typing import Dict, Optional, Tuple

import httpx

from ai_service.connectors.intelowl.mock_intelowl import MockIntelOwlConnector
from ai_service.connectors.models.event import ThreatIntelResult
from config.settings import settings

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
COOLDOWN_SECONDS = 300


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _neutral(ip: str, source: str, note: str) -> ThreatIntelResult:
    return ThreatIntelResult(indicator=ip, indicator_type="ip", reputation_score=0.0,
                             is_malicious=False, source=source, details={"note": note})


class AbuseIPDBConnector(MockIntelOwlConnector):
    """AbuseIPDB for IPs, simulated provider for the other indicator types."""

    def __init__(self, api_key: Optional[str] = None, client_factory=None):
        super().__init__()
        self.api_key = api_key if api_key is not None else settings.abuseipdb_api_key
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=float(settings.ti_timeout_seconds)))
        self._cache: Dict[str, Tuple[float, ThreatIntelResult]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._paused_until = 0.0
        self.requests_made = 0

    async def check_ip(self, ip: str) -> ThreatIntelResult:
        if ip in self.malicious_ips:                # documentation addresses of the simulated scenario
            return await super().check_ip(ip)
        if not is_public_ip(ip):
            return _neutral(ip, "local_network", "Adresse privée ou locale : non interrogée.")

        ttl = float(settings.ti_cache_hours) * 3600
        cached = self._cache.get(ip)
        if cached and time.monotonic() - cached[0] < ttl:
            return cached[1]

        lock = self._locks.setdefault(ip, asyncio.Lock())
        async with lock:
            cached = self._cache.get(ip)            # another task may have filled it
            if cached and time.monotonic() - cached[0] < ttl:
                return cached[1]
            if time.monotonic() < self._paused_until:
                return _neutral(ip, "abuseipdb_unavailable", "Fournisseur en pause après une erreur.")
            result = await self._query(ip)
            if result.source == "abuseipdb":        # failures are not cached
                self._cache[ip] = (time.monotonic(), result)
            return result

    async def _query(self, ip: str) -> ThreatIntelResult:
        self.requests_made += 1
        try:
            async with self._client_factory() as client:
                response = await client.get(
                    API_URL,
                    params={"ipAddress": ip, "maxAgeInDays": int(settings.abuseipdb_max_age_days)},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                )
            if response.status_code in (401, 403, 429):
                self._paused_until = time.monotonic() + COOLDOWN_SECONDS
                logger.warning("AbuseIPDB refused the request (HTTP %s): pause %ss",
                               response.status_code, COOLDOWN_SECONDS)
                return _neutral(ip, "abuseipdb_unavailable", f"HTTP {response.status_code}")
            response.raise_for_status()
            data = response.json()["data"]
            score = float(data.get("abuseConfidenceScore", 0))
        except Exception as exc:                    # network, timeout, malformed answer
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return _neutral(ip, "abuseipdb_unavailable", type(exc).__name__)

        return ThreatIntelResult(
            indicator=ip, indicator_type="ip", reputation_score=score,
            is_malicious=score >= float(settings.abuseipdb_min_score),
            source="abuseipdb",
            details={
                "country": data.get("countryCode") or "Unknown",
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
                "reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "whitelisted": bool(data.get("isWhitelisted")),
                "max_age_days": int(settings.abuseipdb_max_age_days),
            },
        )


def build_connector():
    """AbuseIPDB when a key is configured, otherwise the simulated provider."""
    if settings.abuseipdb_api_key:
        return AbuseIPDBConnector()
    from ai_service.connectors.intelowl.mock_intelowl import mock_intelowl
    return mock_intelowl
