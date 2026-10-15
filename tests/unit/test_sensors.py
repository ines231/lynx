import asyncio
import json
from datetime import datetime, timedelta

import pytest

from ai_service.connectors import sources
from ai_service.connectors.sensors.falco import falco_to_event
from ai_service.connectors.sensors.suricata import suricata_to_event
from ai_service.connectors.sensors.common import parse_time, read_json_lines
from ai_service.risk.pipeline import public_view, run_analysis
from config.settings import settings

NOW = datetime(2026, 10, 15, 21, 0, 0)


def _falco(when, rule="Read sensitive file untrusted", priority="Warning",
           tags=("filesystem", "mitre_credential_access", "T1555"), **fields):
    return {
        "time": when.strftime("%Y-%m-%dT%H:%M:%S.123456789Z"),
        "rule": rule, "priority": priority, "hostname": "lab-vm", "source": "syscall",
        "tags": list(tags), "output": "...",
        "output_fields": {"proc.name": "cat", "proc.cmdline": "cat /etc/shadow",
                          "user.name": "root", "fd.name": "/etc/shadow", **fields},
    }


def _suricata(when, signature="ET SCAN Nmap Scripting Engine User-Agent Detected", **extra):
    return {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.123456+0100"),
        "event_type": "alert", "src_ip": "10.0.0.5", "src_port": 51234,
        "dest_ip": "10.0.0.9", "dest_port": 22, "proto": "TCP",
        "alert": {"signature": signature, "signature_id": 2024364, "severity": 2,
                  "category": "Web Application Attack", **extra},
    }


# ------------------------------------------------------------ adapters
def test_timestamps_with_nanoseconds_and_offsets_are_normalised_to_utc():
    assert parse_time("2026-10-15T20:12:44.123456789Z") == datetime(2026, 10, 15, 20, 12, 44, 123456)
    assert parse_time("2026-10-15T20:12:44.123456+0100") == datetime(2026, 10, 15, 19, 12, 44, 123456)
    assert parse_time("not a date") is None and parse_time(None) is None


def test_falco_alert_becomes_a_security_event():
    event = falco_to_event(_falco(NOW))

    assert event.event_type == "credential_use"               # from the ATT&CK id T1555
    assert event.severity == "medium"                         # Warning
    assert event.user == "root" and event.hostname == "lab-vm"
    assert event.file_path == "/etc/shadow" and event.process_name == "cat"
    assert event.command_line == "cat /etc/shadow"
    assert event.metadata["mitre_ids"] == ["T1555"]           # reused as-is by the MITRE correlator


def test_falco_network_tuple_and_rule_keywords():
    event = falco_to_event(_falco(
        NOW, rule="Upload of data with curl", tags=("network",),
        **{"fd.name": "10.0.0.5:44444->203.0.113.9:4444"}))

    assert event.source_ip == "10.0.0.5" and event.destination_ip == "203.0.113.9"
    assert event.destination_port == 4444
    assert event.event_type == "data_transfer"                # keyword "upload", no ATT&CK id


def test_unusable_falco_documents_are_ignored():
    assert falco_to_event({"hello": "world"}) is None
    assert falco_to_event({"rule": "x", "time": "garbage"}) is None
    assert falco_to_event("nope") is None


def test_suricata_scan_alert():
    event = suricata_to_event(_suricata(NOW))

    assert event.event_type == "port_scan" and event.severity == "medium"
    assert (event.source_ip, event.destination_ip, event.destination_port) == ("10.0.0.5", "10.0.0.9", 22)
    assert event.timestamp.replace(microsecond=0) == NOW - timedelta(hours=1)   # +0100 -> UTC


def test_suricata_uses_the_mitre_metadata_and_ignores_other_event_types():
    event = suricata_to_event(_suricata(NOW, signature="ET POLICY something",
                                        metadata={"mitre_technique_id": ["T1048"]}))
    assert event.event_type == "data_transfer" and event.metadata["mitre_ids"] == ["T1048"]

    assert suricata_to_event({"event_type": "dns", "timestamp": "2026-10-15T20:00:00+0000"}) is None


def test_log_reader_skips_damaged_lines_and_reads_only_the_tail(tmp_path):
    path = tmp_path / "events.json"
    path.write_text('{"a": 1}\nnot json\n{"b": 2}\n{"c": 3', encoding="utf-8")

    assert list(read_json_lines(str(path))) == [{"a": 1}, {"b": 2}]


# ------------------------------------------------------------ source + pipeline
@pytest.fixture
def sensor_files(tmp_path, monkeypatch):
    """A week of normal Falco activity, then an attack in the last hour."""
    falco, eve = tmp_path / "falco.json", tmp_path / "eve.json"
    lines = []
    for day in range(1, 6):
        for hour in (9, 10, 14):
            when = NOW - timedelta(days=day, hours=NOW.hour - hour)
            lines.append(json.dumps(_falco(when, rule="Launch Package Management Process",
                                           priority="Notice", tags=("process",),
                                           **{"fd.name": "", "proc.cmdline": "apt update"})))
    attack = [
        _falco(NOW - timedelta(minutes=40), rule="Read sensitive file untrusted"),
        _falco(NOW - timedelta(minutes=30), rule="Schedule Cron Jobs", tags=("T1053.003",),
               **{"proc.cmdline": "crontab -e", "fd.name": "/etc/crontab"}),
        _falco(NOW - timedelta(minutes=20), rule="Upload of data with curl",
               tags=("network",), **{"fd.name": "10.0.0.5:44444->203.0.113.9:4444"}),
    ]
    falco.write_text("\n".join(lines + [json.dumps(a) for a in attack]) + "\n", encoding="utf-8")
    eve.write_text("\n".join(json.dumps(_suricata(NOW - timedelta(minutes=50 - i))) for i in range(3)) + "\n",
                   encoding="utf-8")

    monkeypatch.setattr(settings, "falco_events_file", str(falco))
    monkeypatch.setattr(settings, "suricata_eve_file", str(eve))
    monkeypatch.setattr(settings, "sensor_window_hours", 2)
    monkeypatch.setattr(settings, "sensor_baseline_days", 7)
    monkeypatch.setattr(settings, "sensor_min_severity", "low")
    return falco, eve


def _real_source():
    return sources.SensorSource(now=lambda: NOW)


def test_sensor_source_separates_the_window_from_the_baseline(sensor_files):
    source = _real_source()
    window = asyncio.run(source.attack_events())
    baseline = asyncio.run(source.baseline_events(30))

    assert len(window) == 6 and len(baseline) == 15
    assert {e.event_type for e in window} >= {"port_scan", "scheduled_task", "data_transfer"}
    assert max(e.timestamp for e in baseline) <= min(e.timestamp for e in window)
    info = source.describe()
    assert info["is_real"] and info["analysed_events"] == 6 and info["sensors"] == ["falco", "suricata"]


def test_severity_filter_applies_to_both_sides(sensor_files, monkeypatch):
    monkeypatch.setattr(settings, "sensor_min_severity", "medium")
    source = _real_source()

    assert len(asyncio.run(source.attack_events())) == 6      # Warning / medium alerts
    with pytest.raises(sources.SourceError):                  # baseline events are "Notice"
        asyncio.run(source.baseline_events(30))


def test_missing_files_and_empty_windows_give_clear_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "falco_events_file", str(tmp_path / "nope.json"))
    monkeypatch.setattr(settings, "suricata_eve_file", str(tmp_path / "nope2.json"))
    with pytest.raises(sources.SourceError) as missing:
        asyncio.run(sources.SensorSource().attack_events())
    assert missing.value.status_code == 503 and "Falco" in str(missing.value)

    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr(settings, "falco_events_file", str(empty))
    with pytest.raises(sources.SourceError) as none:
        asyncio.run(sources.SensorSource().attack_events())
    assert none.value.status_code == 404 and "Atomic Red Team" in str(none.value)


def test_full_analysis_runs_on_real_sensor_data(sensor_files, monkeypatch):
    monkeypatch.setattr(sources, "get_source", lambda name=None: _real_source())
    monkeypatch.setattr("ai_service.risk.pipeline.get_source", lambda name=None: _real_source())

    analysis = asyncio.run(run_analysis(normal_count=30, source="sensors"))
    view = public_view(analysis)

    assert view["data_source"]["is_real"] is True and "Falco" in view["data_source"]["label"]
    assert len(view["event_risks"]) == 6
    assert view["chi_square"]["n_observed"] == 6
    # ATT&CK ids carried by the sensor are used as they are by the correlator
    techniques = {t["technique_id"] for a in analysis["reports"] for t in a["mitre_attack_mapping"]}
    assert techniques & {"T1053", "T1053.003", "T1555"}


def test_mock_source_is_unchanged_and_flagged_as_simulated():
    analysis = asyncio.run(run_analysis(normal_count=30, seed=7))

    assert analysis["data_source"]["is_real"] is False
    assert analysis["data_source"]["label"] == "Données simulées"
    assert analysis["data_source"]["analysed_events"] == 7
    with pytest.raises(ValueError):
        sources.get_source("wazuh")
