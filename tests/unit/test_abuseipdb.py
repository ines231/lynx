"""AbuseIPDB connector: no real network, the HTTP client is replaced by a fake."""

import asyncio

from ai_service.connectors.intelowl.abuseipdb import AbuseIPDBConnector, build_connector, is_public_ip
from config.settings import settings


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    def __init__(self, log, responses):
        self.log, self.responses = log, responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None, headers=None):
        self.log.append((params["ipAddress"], headers["Key"]))
        await asyncio.sleep(0)
        item = self.responses(params["ipAddress"])
        if isinstance(item, Exception):
            raise item
        return item


def _answer(score, country="RU"):
    return FakeResponse(200, {"data": {"abuseConfidenceScore": score, "countryCode": country,
                                       "isp": "Example ISP", "totalReports": 42,
                                       "usageType": "Data Center", "isWhitelisted": False}})


def _connector(responses):
    log = []
    return AbuseIPDBConnector(api_key="k", client_factory=lambda: FakeClient(log, responses)), log


def test_public_ip_detection():
    assert is_public_ip("8.8.8.8") and is_public_ip("41.231.245.33")
    for ip in ("127.0.0.1", "192.168.20.134", "10.0.0.5", "169.254.1.1", "not-an-ip"):
        assert not is_public_ip(ip)


def test_malicious_above_threshold_and_details_kept():
    connector, log = _connector(lambda ip: _answer(87))
    result = asyncio.run(connector.check_ip("45.155.205.1"))

    assert result.source == "abuseipdb" and result.is_malicious
    assert result.reputation_score == 87
    assert result.details["country"] == "RU" and result.details["reports"] == 42
    assert log == [("45.155.205.1", "k")]


def test_low_score_is_not_malicious(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_min_score", 50)
    connector, _ = _connector(lambda ip: _answer(10))
    assert not asyncio.run(connector.check_ip("8.8.8.8")).is_malicious


def test_private_addresses_are_never_sent_out():
    connector, log = _connector(lambda ip: _answer(99))
    result = asyncio.run(connector.check_ip("192.168.20.134"))

    assert log == [] and result.source == "local_network" and not result.is_malicious


def test_results_are_cached_and_concurrent_lookups_share_one_call():
    connector, log = _connector(lambda ip: _answer(60))

    async def run():
        return await asyncio.gather(*(connector.check_ip("45.155.205.1") for _ in range(5)))

    results = asyncio.run(run())
    asyncio.run(connector.check_ip("45.155.205.1"))

    assert len(log) == 1 and all(r.is_malicious for r in results)


def test_failure_gives_a_neutral_result_not_a_random_one():
    connector, _ = _connector(lambda ip: TimeoutError("boom"))
    result = asyncio.run(connector.check_ip("45.155.205.1"))

    assert result.source == "abuseipdb_unavailable"
    assert not result.is_malicious and result.reputation_score == 0
    assert connector._cache == {}                   # failures are not cached


def test_quota_error_pauses_the_provider():
    connector, log = _connector(lambda ip: FakeResponse(429))
    first = asyncio.run(connector.check_ip("45.155.205.1"))
    second = asyncio.run(connector.check_ip("45.155.205.2"))

    assert first.source == second.source == "abuseipdb_unavailable"
    assert len(log) == 1                            # the second call never left


def test_simulated_scenario_addresses_still_use_the_mock():
    connector, log = _connector(lambda ip: _answer(0))
    result = asyncio.run(connector.check_ip("203.0.113.45"))

    assert result.source == "mock_intelowl" and result.is_malicious and log == []


def test_build_connector_depends_on_the_key(monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    assert build_connector().__class__.__name__ == "MockIntelOwlConnector"
    monkeypatch.setattr(settings, "abuseipdb_api_key", "secret")
    assert isinstance(build_connector(), AbuseIPDBConnector)
