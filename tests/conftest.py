"""Shared test setup."""

import pytest


@pytest.fixture(autouse=True)
def _simulated_data_by_default(monkeypatch):
    """Tests assume the simulated source, whatever DATA_SOURCE says in config/.env.

    On a machine wired to real sensors (DATA_SOURCE=sensors) the tests must not read
    the real logs; tests that need the sensors pass ``source="sensors"`` explicitly.
    """
    from config.settings import settings

    monkeypatch.setattr(settings, "data_source", "mock", raising=False)
    monkeypatch.setattr(settings, "abuseipdb_api_key", "", raising=False)   # no real lookups in tests

    # the enrichment service picked its connector at import time: pin the simulated one
    from ai_service.connectors.intelowl.mock_intelowl import mock_intelowl
    from ai_service.enrichment.enrichment_service import enrichment_service

    monkeypatch.setattr(enrichment_service, "intelowl", mock_intelowl)
