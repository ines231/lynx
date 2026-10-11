from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_service.app.api import risk

app = FastAPI()
app.include_router(risk.router)
client = TestClient(app)


def test_analyze_detects_the_attack_scenario():
    response = client.get("/api/risk/analyze?normal_count=30&seed=7")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert len(data["event_risks"]) == 7

    chi = data["chi_square"]
    assert chi["is_significant"]
    assert chi["p_value"] < 0.01
    assert {"port_scan", "lateral_movement"} <= set(chi["new_categories"])

    # chi_square_probability = 1 - p_value -> close to 1 for this attack
    for event in data["event_risks"]:
        assert event["chi_square_probability"] > 0.99


def test_analyze_is_reproducible_with_a_seed():
    first = client.get("/api/risk/analyze?seed=11").json()["event_risks"]
    second = client.get("/api/risk/analyze?seed=11").json()["event_risks"]

    def figures(rows):
        return [
            (r["anomaly_probability"], r["annual_loss_expectancy"], r["value_at_risk_95"])
            for r in rows
        ]

    assert figures(first) == figures(second)


def test_every_probability_is_a_valid_probability():
    rows = client.get("/api/risk/analyze?seed=3").json()["event_risks"]

    for row in rows:
        assert 0.0 <= row["anomaly_probability"] <= 1.0
        assert 0.0 <= row["chi_square_probability"] <= 1.0
        assert row["annual_loss_expectancy"] >= 0
        assert row["value_at_risk_99"] >= row["value_at_risk_95"] >= 0


def test_the_exfiltration_event_is_the_highest_risk():
    rows = client.get("/api/risk/analyze?seed=5").json()["event_risks"]
    top = max(rows, key=lambda r: r["annual_loss_expectancy"])

    assert top["event"] == "file_access"
    assert top["priority"] in {"CRITICAL", "HIGH"}


def test_demo_endpoint_still_works():
    response = client.get("/api/risk/demo")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
