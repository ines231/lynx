from ai_service.risk.hunting_priority import assess


def _event(event_type, severity="medium", intel=None):
    return {"event_type": event_type, "severity": severity, "threat_intel": intel or {}}


def test_serious_unusual_malicious_event_must_be_investigated():
    intel = {"destination_ip": {"is_malicious": True, "reputation_score": 80}}
    result = assess(_event("data_transfer", "high", intel), 0.8, "exfiltration")

    assert result["level"] == "INVESTIGATE" and result["score"] >= 55
    assert any("malveillante" in r for r in result["reasons"])
    assert any("exfiltration" in r for r in result["reasons"])


def test_ordinary_event_close_to_the_baseline_is_noise():
    result = assess(_event("network_connection", "low"), 0.1, "unknown")

    assert result["level"] == "NOISE" and result["score"] < 35
    assert result["reasons"] == ["Aucun signal fort : comportement proche de la baseline"]


def test_score_grows_with_each_signal():
    base = assess(_event("port_scan", "low"), 0.2, "reconnaissance")["score"]

    assert assess(_event("port_scan", "low"), 0.9, "reconnaissance")["score"] > base
    assert assess(_event("port_scan", "high"), 0.2, "reconnaissance")["score"] > base
    assert assess(_event("privilege_escalation", "low"), 0.2, "reconnaissance")["score"] > base
    bad_ip = {"source_ip": {"is_malicious": True, "reputation_score": 90}}
    assert assess(_event("port_scan", "low", bad_ip), 0.2, "reconnaissance")["score"] > base


def test_score_is_bounded_and_levels_are_ordered():
    top = assess(_event("data_transfer", "critical",
                        {"source_ip": {"is_malicious": True, "reputation_score": 100}}), 1.0, "exfiltration")
    low = assess(_event("x", "low"), 0.0, "unknown")

    assert 0 <= low["score"] < top["score"] <= 100
    assert top["level"] == "INVESTIGATE" and low["level"] == "NOISE"


def test_pipeline_attaches_the_hunting_priority_to_every_event():
    import asyncio
    from ai_service.risk.pipeline import public_view, run_analysis

    view = public_view(asyncio.run(run_analysis(normal_count=30, seed=7)))

    assert all({"hunt_score", "hunt_level", "hunt_label", "hunt_reasons"} <= set(r)
               for r in view["event_risks"])
    counts = view["summary"]["hunting"]
    assert sum(counts.values()) == len(view["event_risks"])
