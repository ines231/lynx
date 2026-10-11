from datetime import datetime

from ai_service.risk.anomaly_probability import AnomalyProbability
from ai_service.risk.common import is_private_ip

model = AnomalyProbability()

BASELINE = {
    "time_patterns": {"active_hours": [9, 10, 11], "hour_mean": 10.0, "hour_std": 2.0},
    "process_patterns": {"typical_processes": ["explorer.exe", "notepad.exe"]},
    "network_patterns": {
        "typical_destinations": ["192.168.1.10"],
        "typical_ports": [443, 80],
    },
    "event_types": {"login": 12, "file_access": 10, "dns_query": 8},
}


def test_ip_matching_is_exact_not_substring():
    """'192.168.1.10' used to match '192.168.1.100' (substring test)."""
    typical = {"destination_ip": "192.168.1.10", "destination_port": 443}
    other = {"destination_ip": "192.168.1.100", "destination_port": 443}

    assert model._network_anomaly_probability(typical, BASELINE) == 0.1
    assert model._network_anomaly_probability(other, BASELINE) > 0.1


def test_private_ip_detection_uses_real_ranges():
    assert is_private_ip("10.1.2.3")
    assert is_private_ip("192.168.1.50")
    assert is_private_ip("172.16.0.1") and is_private_ip("172.31.255.1")
    assert not is_private_ip("172.15.0.1")      # public, was treated as private
    assert not is_private_ip("172.32.0.1")      # public, was treated as private
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("not-an-ip")


def test_missing_port_is_not_assumed_typical():
    no_port = {"destination_ip": "192.168.1.10", "destination_port": None}
    assert model._network_anomaly_probability(no_port, BASELINE) > 0.1


def test_time_score_is_two_sided():
    """An hour close to the mean must not look 50% anomalous."""
    close = {"timestamp": datetime(2026, 1, 5, 12, 0)}     # not in active_hours, z = 1
    far = {"timestamp": datetime(2026, 1, 5, 3, 0)}        # z = 3.5

    assert model._time_anomaly_probability(close, BASELINE) < 0.7
    assert model._time_anomaly_probability(far, BASELINE) > 0.9
    assert model._time_anomaly_probability(
        {"timestamp": datetime(2026, 1, 5, 10, 0)}, BASELINE) == 0.1


def test_rare_event_type_scores_higher_than_common_one():
    common = {"event_type": "login"}
    unseen = {"event_type": "privilege_escalation"}

    common_p = model._event_type_anomaly_probability(common, BASELINE)
    unseen_p = model._event_type_anomaly_probability(unseen, BASELINE)

    assert common_p <= 0.15
    assert unseen_p > 0.85


def test_baseline_without_event_types_keeps_working():
    legacy = {k: v for k, v in BASELINE.items() if k != "event_types"}
    event = {"event_type": "login", "timestamp": datetime(2026, 1, 5, 10, 0)}

    prob, details = model.calculate_probability(event, legacy)

    assert 0.0 <= prob <= 1.0
    assert "event_type_anomaly" not in details


def test_attack_event_scores_higher_than_routine_event():
    routine = {
        "event_type": "login",
        "timestamp": datetime(2026, 1, 5, 10, 0),
        "process_name": "explorer.exe",
        "destination_ip": "192.168.1.10",
        "destination_port": 443,
    }
    attack = {
        "event_type": "lateral_movement",
        "timestamp": datetime(2026, 1, 5, 3, 0),
        "process_name": "psexec.exe",
        "destination_ip": "203.0.113.45",
        "destination_port": 445,
    }

    routine_p, _ = model.calculate_probability(routine, BASELINE)
    attack_p, _ = model.calculate_probability(attack, BASELINE)

    assert routine_p < 0.2
    assert attack_p > 0.6
    assert 0.0 <= attack_p <= 1.0
