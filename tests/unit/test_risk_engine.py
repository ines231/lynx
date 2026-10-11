import numpy as np

from ai_service.risk.baseline_model import BaselineModel
from ai_service.risk.common import fair_category, is_sensitive_path
from ai_service.risk.monte_carlo_fair import MonteCarloFAIR
from ai_service.risk.risk_treatment import RiskTreatment


# ----------------------------------------------------------------- helpers
def test_sensitive_path_detection():
    # "Financial" was missed by the old "finance" keyword
    assert is_sensitive_path("C:\\Data\\Financial\\reports.xlsx")
    assert is_sensitive_path("C:\\Data\\HR\\salaries.xlsx")
    assert is_sensitive_path("\\\\server\\Finance\\Q4_Budget.xlsx")
    assert is_sensitive_path("C:\\Confidential\\secrets.txt")
    # "hr" inside unrelated words used to match
    assert not is_sensitive_path("C:\\Program Files\\Google\\Chrome\\chrome.exe")
    assert not is_sensitive_path("C:\\Users\\shared\\notes.txt")
    assert not is_sensitive_path(None)


def test_fair_category_mapping():
    assert fair_category({"event_type": "port_scan"}) == "reconnaissance"
    assert fair_category({"event_type": "service_installation"}) == "persistence"
    assert fair_category({"event_type": "lateral_movement"}) == "lateral_movement"
    external = {"event_type": "file_access", "destination_ip": "203.0.113.45"}
    internal = {"event_type": "file_access", "destination_ip": "192.168.1.100"}
    assert fair_category(external) == "exfiltration"
    assert fair_category(internal) == "file_access"


# -------------------------------------------------------------------- FAIR
def test_simulated_mean_matches_analytic_ale():
    fair = MonteCarloFAIR(simulations=50000, seed=1)
    losses = fair._monte_carlo_loss_distribution(lef=2.0, plm=10000.0)

    assert np.isclose(losses.mean(), 2.0 * 10000.0, rtol=0.03)


def test_simulation_is_reproducible_and_vectorised_result_is_valid():
    fair = MonteCarloFAIR(simulations=5000, seed=5)
    a = fair._monte_carlo_loss_distribution(0.5, 8000.0)
    b = fair._monte_carlo_loss_distribution(0.5, 8000.0)

    assert np.array_equal(a, b)
    assert (a >= 0).all()
    assert 0.2 < (a > 0).mean() < 0.55          # P(at least one event) = 1 - e^-0.5 ~ 0.39


def test_exfiltration_of_financial_file_is_priced_as_exfiltration():
    fair = MonteCarloFAIR(seed=1)
    exfil = {
        "event_type": "file_access",
        "destination_ip": "203.0.113.45",
        "file_path": "C:\\Data\\Financial\\reports.xlsx",
    }
    routine = {"event_type": "file_access", "destination_ip": "192.168.1.100"}

    assert fair._estimate_loss_magnitude(exfil) == 50000 * 3
    assert fair._estimate_loss_magnitude(routine) == 5000.0


def test_calculate_risk_exposes_consistent_metrics():
    fair = MonteCarloFAIR(simulations=20000, seed=3)
    event = {"event_type": "privilege_escalation", "threat_intel": {}}

    metrics = fair.calculate_risk(event, anomaly_prob=0.8)

    assert np.isclose(
        metrics["annual_loss_expectancy"],
        metrics["loss_event_frequency"] * metrics["probable_loss_magnitude"],
    )
    assert np.isclose(
        metrics["loss_event_frequency"],
        metrics["threat_event_frequency"] * metrics["vulnerability"],
    )
    assert 0.0 <= metrics["probability_of_loss"] <= 1.0
    assert metrics["value_at_risk_99"] >= metrics["value_at_risk_95"]
    # annual (unconditional) VaR can never exceed the conditional one
    assert metrics["value_at_risk_95_annual"] <= metrics["value_at_risk_95"] + 1e-9


def test_higher_anomaly_means_higher_risk():
    fair = MonteCarloFAIR(simulations=5000, seed=2)
    event = {"event_type": "lateral_movement", "threat_intel": {}}

    low = fair.calculate_risk(event, 0.1)["annual_loss_expectancy"]
    high = fair.calculate_risk(event, 0.9)["annual_loss_expectancy"]

    assert high > low


# --------------------------------------------------------------- treatment
def test_risk_drivers_are_not_always_loss_magnitude():
    """tef + vulnerability + plm mixed events/year, a probability and dollars,
    so the dollar amount always accounted for ~100% of the 'risk'."""
    drivers = RiskTreatment._identify_risk_drivers(tef=2.0, vulnerability=0.9, plm=5000.0)

    assert "threat_frequency" in drivers
    assert "loss_magnitude" not in drivers


def test_controls_are_deterministic_and_deduplicated():
    treatment = RiskTreatment()
    first = treatment._get_controls_for_event("port_scan reconnaissance", "ACCEPT")
    second = treatment._get_controls_for_event("lateral_movement lateral_movement", "REMEDIATE")

    assert second == treatment._get_controls_for_event("lateral_movement lateral_movement", "REMEDIATE")
    assert len(second) == len(set(second))
    assert first == []   # no control catalogue for reconnaissance


# ---------------------------------------------------------------- baseline
def test_user_baseline_contains_full_distributions():
    events = (
        [{"event_type": "login", "process_name": "explorer.exe", "destination_port": 443}] * 6
        + [{"event_type": "file_access", "process_name": "notepad.exe", "destination_port": 80}] * 3
    )
    baseline = BaselineModel().build_user_baseline("u", events)

    assert baseline["event_types"] == {"login": 6, "file_access": 3}
    assert baseline["process_patterns"]["counts"] == {"explorer.exe": 6, "notepad.exe": 3}
    assert baseline["network_patterns"]["port_counts"] == {"443": 6, "80": 3}


def test_event_type_distribution_is_not_truncated_to_ten():
    events = [{"event_type": f"type_{i}"} for i in range(15)]
    baseline = BaselineModel().build_user_baseline("u", events)
    assert len(baseline["event_types"]) == 15
