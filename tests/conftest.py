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
