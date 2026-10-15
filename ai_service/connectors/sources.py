"""
Where the events of an analysis come from.

* ``mock``     simulated events (``mock_wazuh``): always available, used for demos.
* ``sensors``  real alerts written by Falco (host) and Suricata (network).

The risk pipeline only needs two lists of ``SecurityEvent``: the **baseline**
(what is normal) and the **window** to analyse. A source provides both, and
describes itself so that the API, the dashboard and the PDF can say whether the
figures come from real or simulated data.
"""

import asyncio
import os
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from config.settings import settings
from ai_service.connectors.models.event import SecurityEvent
from ai_service.connectors.sensors.common import SEVERITY_ORDER, read_json_lines
from ai_service.connectors.sensors.falco import falco_to_event
from ai_service.connectors.sensors.suricata import suricata_to_event
from ai_service.connectors.wazuh.mock_wazuh import mock_wazuh

SOURCE_NAMES = ("mock", "sensors")

# The baseline of the mock source must describe NORMAL behaviour only.
NORMAL_EVENT_TYPES = ["login", "process_execution", "file_access", "network_connection", "dns_query"]


class SourceError(Exception):
    """A source cannot provide data (missing file, no alert...). Carries an HTTP status."""

    def __init__(self, message: str, status_code: int = 404):
        super().__init__(message)
        self.status_code = status_code


class MockSource:
    name = "mock"
    is_real = False

    def __init__(self):
        self._info: Dict[str, Any] = {}

    async def baseline_events(
        self, count: int, window_hours: Optional[float] = None
    ) -> List[SecurityEvent]:
        events = mock_wazuh.generate_events(count=count, event_types=NORMAL_EVENT_TYPES)
        self._info["baseline_events"] = len(events)
        return events

    async def attack_events(self, window_hours: Optional[float] = None) -> List[SecurityEvent]:
        events = mock_wazuh.generate_attack_scenario()
        self._info["analysed_events"] = len(events)
        return events

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_real": False,
            "label": "Données simulées",
            "description": "Événements générés par mock_wazuh (scénario d'attaque écrit à la main).",
            **self._info,
        }


class SensorSource:
    """Real alerts read from the JSON files of Falco and/or Suricata."""

    name = "sensors"
    is_real = True

    def __init__(self, now: Optional[Callable[[], datetime]] = None):
        # one reference instant per analysis, shared by the window and the baseline
        self._anchor = (now or datetime.utcnow)()
        self._info: Dict[str, Any] = {}

    # -------------------------------------------------------------- reading
    def _files(self):
        files = []
        if settings.falco_events_file and os.path.exists(settings.falco_events_file):
            files.append(("falco", settings.falco_events_file, falco_to_event))
        if settings.suricata_eve_file and os.path.exists(settings.suricata_eve_file):
            files.append(("suricata", settings.suricata_eve_file, suricata_to_event))
        if not files:
            raise SourceError(
                "Aucun fichier de capteur trouvé. Installe Falco et/ou Suricata, ou renseigne "
                "FALCO_EVENTS_FILE / SURICATA_EVE_FILE dans config/.env "
                f"(cherchés : {settings.falco_events_file}, {settings.suricata_eve_file}).",
                status_code=503,
            )
        return files

    def _read(self, start: datetime, end: datetime, limit: int) -> List[SecurityEvent]:
        minimum = SEVERITY_ORDER.get(str(settings.sensor_min_severity).lower(), 0)
        events: List[SecurityEvent] = []
        used = []
        for sensor, path, convert in self._files():
            used.append(sensor)
            for document in read_json_lines(path, settings.sensor_read_max_mb):
                event = convert(document)
                if event is None or not (start <= event.timestamp < end):
                    continue
                if SEVERITY_ORDER.get(event.severity, 0) < minimum:
                    continue
                events.append(event)
        events.sort(key=lambda e: e.timestamp)
        self._info["sensors"] = used
        return events[-limit:]          # the newest ones

    # ------------------------------------------------------------ interface
    def _window(self, window_hours: Optional[float]):
        hours = float(window_hours or settings.sensor_window_hours)
        return hours, self._anchor - timedelta(hours=hours), self._anchor

    async def attack_events(self, window_hours: Optional[float] = None) -> List[SecurityEvent]:
        hours, start, end = self._window(window_hours)
        events = await asyncio.to_thread(self._read, start, end, settings.sensor_max_events)
        if not events:
            raise SourceError(
                f"Aucune alerte de gravité ≥ « {settings.sensor_min_severity} » dans les "
                f"{hours:g} dernières heures. Lance une attaque de test (Atomic Red Team) ou "
                "élargis la fenêtre (paramètre window_hours).",
            )
        self._info.update(window_start=start.isoformat(), window_end=end.isoformat(),
                          window_hours=hours, analysed_events=len(events))
        return events

    async def baseline_events(
        self, count: int, window_hours: Optional[float] = None
    ) -> List[SecurityEvent]:
        # the baseline is the history BEFORE the analysed window (`count` is ignored:
        # real baselines use every alert of the reference period)
        _, window_start, _ = self._window(window_hours)
        start = window_start - timedelta(days=float(settings.sensor_baseline_days))
        events = await asyncio.to_thread(
            self._read, start, window_start, settings.sensor_baseline_max_events)
        if not events:
            raise SourceError(
                f"Aucune alerte dans l'historique de référence ({settings.sensor_baseline_days:g} "
                f"jours avant la fenêtre analysée). La baseline décrit le comportement normal : "
                "laisse les capteurs tourner (ou réduis window_hours) avant d'analyser une attaque.",
            )
        self._info["baseline_events"] = len(events)
        self._info.update(baseline_start=start.isoformat(), baseline_end=window_start.isoformat())
        return events

    def describe(self) -> Dict[str, Any]:
        sensors = ", ".join(s.capitalize() for s in self._info.get("sensors", [])) or "capteurs"
        return {
            "name": self.name,
            "is_real": True,
            "label": f"Données réelles ({sensors})",
            "description": "Alertes lues dans les fichiers JSON des capteurs de sécurité.",
            **self._info,
        }


def get_source(name: Optional[str] = None):
    """A fresh source (sources keep per-analysis information)."""
    choice = str(name or settings.data_source or "mock").lower()
    if choice == "mock":
        return MockSource()
    if choice == "sensors":
        return SensorSource()
    raise ValueError(f"Source inconnue {choice!r} (valeurs : {', '.join(SOURCE_NAMES)})")
