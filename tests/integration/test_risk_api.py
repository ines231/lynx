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


def test_analyze_returns_an_analysis_id():
    data = client.get("/api/risk/analyze?seed=7").json()

    assert data["analysis_id"]
    assert data["chi_square"]["method"] in {"asymptotic", "monte_carlo"}


def test_report_pdf_for_the_analysis_shown_on_the_dashboard():
    analysis_id = client.get("/api/risk/analyze?seed=7").json()["analysis_id"]

    response = client.get(f"/api/risk/report.pdf?analysis_id={analysis_id}")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert analysis_id in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")


def test_report_pdf_with_an_unknown_analysis_id_is_gone():
    response = client.get("/api/risk/report.pdf?analysis_id=doesnotexist")

    assert response.status_code == 410


def test_report_pdf_without_an_id_runs_a_fresh_analysis():
    response = client.get("/api/risk/report.pdf?seed=3")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
