import numpy as np
from scipy import stats

from ai_service.risk.chi_square_tests import ChiSquareTests

BASELINE = {
    "event_types": {
        "login": 8,
        "file_access": 8,
        "dns_query": 7,
        "process_execution": 7,
    }
}


def _events(counts, key="event_type"):
    return [{key: name} for name, n in counts.items() for _ in range(n)]


def test_normal_window_gets_low_anomaly_score():
    """A window that follows the baseline must NOT look anomalous.

    (The old code returned the raw p-value when the test was not significant,
    so a perfectly normal window could score ~0.9.)
    """
    window = _events({"login": 8, "file_access": 8, "dns_query": 7, "process_execution": 7})
    score, details = ChiSquareTests().test_event_type_distribution(window, BASELINE)

    assert not details["is_significant"]
    assert details["p_value"] > 0.9
    assert score < 0.1
    assert score == 1.0 - details["p_value"]


def test_attack_window_with_unseen_types_is_significant():
    window = _events({"port_scan": 3, "privilege_escalation": 1,
                      "service_installation": 1, "lateral_movement": 1, "file_access": 1})
    score, details = ChiSquareTests().test_event_type_distribution(window, BASELINE)

    assert details["is_significant"]
    assert details["p_value"] < 0.01
    assert score > 0.99
    assert set(details["new_categories"]) == {
        "port_scan", "privilege_escalation", "service_installation", "lateral_movement"
    }
    # 7 events and 8 categories -> expected counts < 5 -> exact Monte-Carlo test
    assert details["method"] == "monte_carlo"


def test_score_increases_with_deviation():
    chi = ChiSquareTests()
    mild = _events({"login": 6, "file_access": 8, "dns_query": 7, "process_execution": 7, "port_scan": 1})
    strong = _events({"login": 1, "file_access": 1, "port_scan": 12, "lateral_movement": 14})

    mild_score, _ = chi.test_event_type_distribution(mild, BASELINE)
    strong_score, _ = chi.test_event_type_distribution(strong, BASELINE)

    assert strong_score > mild_score


def test_result_is_deterministic():
    window = _events({"port_scan": 3, "login": 2})
    first = ChiSquareTests().test_event_type_distribution(window, BASELINE)[0]
    second = ChiSquareTests().test_event_type_distribution(window, BASELINE)[0]
    assert first == second


def test_asymptotic_method_matches_scipy():
    """With large expected counts the p-value must equal scipy's chi-square."""
    chi = ChiSquareTests()
    window = _events({"login": 140, "file_access": 100, "dns_query": 130, "process_execution": 130})
    _, details = chi.test_event_type_distribution(window, BASELINE)

    assert details["method"] == "asymptotic"

    # same smoothed expectation, computed independently
    names = ["login", "file_access", "dns_query", "process_execution"]
    base = np.array([BASELINE["event_types"][n] for n in names], dtype=float)
    probs = (base + 0.5) / (base.sum() + 0.5 * len(names))
    obs = np.array([140, 100, 130, 130], dtype=float)
    expected = probs * obs.sum()
    ref_stat, ref_p = stats.chisquare(obs, expected)

    assert np.isclose(details["chi2_statistic"], ref_stat)
    assert np.isclose(details["p_value"], ref_p)


def test_edge_cases():
    chi = ChiSquareTests()
    assert chi.test_event_type_distribution([], BASELINE) == (0.0, {"test": "no_data"})
    assert chi.test_event_type_distribution([{"event_type": "login"}], {}) == (
        0.0, {"test": "no_baseline"})


def test_process_distribution_uses_baseline_counts():
    baseline = {"process_patterns": {"counts": {"explorer.exe": 20, "notepad.exe": 10}}}
    normal = _events({"explorer.exe": 20, "notepad.exe": 10}, key="process_name")
    odd = _events({"psexec.exe": 8, "powershell.exe": 7}, key="process_name")

    normal_score, _ = ChiSquareTests().test_process_distribution(normal, baseline)
    odd_score, odd_details = ChiSquareTests().test_process_distribution(odd, baseline)

    assert normal_score < 0.1
    assert odd_score > 0.99 and odd_details["is_significant"]


def test_process_distribution_falls_back_to_typical_list():
    baseline = {"process_patterns": {"typical_processes": ["explorer.exe", "notepad.exe"]}}
    events = _events({"explorer.exe": 5, "notepad.exe": 5}, key="process_name")
    score, details = ChiSquareTests().test_process_distribution(events, baseline)
    assert details["test"] == "process_distribution"
    assert score < 0.5


def test_port_distribution_normal_vs_unusual():
    baseline = {"network_patterns": {"port_counts": {"443": 30, "80": 15, "22": 5}}}
    normal = _events({443: 30, 80: 15, 22: 5}, key="destination_port")
    scan = _events({3389: 10, 445: 10, 23: 10}, key="destination_port")

    normal_score, _ = ChiSquareTests().test_port_distribution(normal, baseline)
    scan_score, scan_details = ChiSquareTests().test_port_distribution(scan, baseline)

    assert normal_score < 0.1
    assert scan_score > 0.99 and scan_details["is_significant"]


def test_severity_distribution():
    baseline = {"severity_distribution": {"low": 40, "medium": 8, "high": 1, "critical": 1}}
    quiet = _events({"low": 40, "medium": 8, "high": 1, "critical": 1}, key="severity")
    noisy = _events({"high": 20, "critical": 20}, key="severity")

    quiet_score, _ = ChiSquareTests().test_severity_distribution(quiet, baseline)
    noisy_score, _ = ChiSquareTests().test_severity_distribution(noisy, baseline)

    assert quiet_score < 0.1
    assert noisy_score > 0.99
