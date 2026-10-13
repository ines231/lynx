import pytest
import asyncio

from ai_service.reports import pdf_report
from ai_service.reports.pdf_report import build_risk_report
from ai_service.risk.pipeline import AnalysisStore, public_view, run_analysis


def _analysis(seed=7):
    return asyncio.run(run_analysis(normal_count=30, seed=seed))


# ------------------------------------------------------------ pipeline
def test_pipeline_is_reproducible_with_a_seed():
    first = public_view(_analysis(seed=11))["event_risks"]
    second = public_view(_analysis(seed=11))["event_risks"]

    def figures(rows):
        return [
            (r["anomaly_probability"], r["annual_loss_expectancy"], r["value_at_risk_95"])
            for r in rows
        ]

    assert figures(first) == figures(second)


def test_public_view_exposes_an_analysis_id_and_the_chi_square_details():
    view = public_view(_analysis())

    assert view["status"] == "success"
    assert view["analysis_id"]
    assert view["chi_square"]["p_value"] < 0.01
    assert view["chi_square"]["method"] in {"asymptotic", "monte_carlo"}
    assert view["summary"]["total_events"] == len(view["event_risks"]) == 7


def test_analysis_store_keeps_the_latest_items_only():
    store = AnalysisStore(max_items=2)
    for name in ("a", "b", "c"):
        store.put({"analysis_id": name})

    assert store.get("a") is None
    assert store.get("b") == {"analysis_id": "b"}
    assert store.get("c") == {"analysis_id": "c"}
    assert len(store) == 2


# ------------------------------------------------------------ PDF
def test_report_is_a_non_trivial_pdf_with_several_pages():
    pdf = build_risk_report(_analysis())

    assert pdf.startswith(b"%PDF")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 10_000
    # one /Type /Page object per page (the report is multi-page)
    assert pdf.count(b"/Type /Page\n") + pdf.count(b"/Type /Page ") >= 4


def test_report_survives_an_empty_analysis():
    empty = {
        "analysis_id": "empty",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "parameters": {"normal_count": 0, "seed": None},
        "baseline": {},
        "events": [],
        "event_risks": [],
        "event_details": [],
        "chi_square": {},
        "attacks": [],
        "reports": [],
        "hypotheses": [],
    }

    assert build_risk_report(empty).startswith(b"%PDF")


# ------------------------------------------------------------ formatting
def test_p_values_are_never_shown_as_zero():
    assert pdf_report._p_value(9.999e-05) == "< 0,0001"
    assert pdf_report._p_value(0.0123) == "0,0123"
    assert pdf_report._p_phrase(9.999e-05) == "p < 0,0001"
    assert pdf_report._p_phrase(0.0123) == "p = 0,0123"


def test_numbers_use_french_separators():
    assert pdf_report._num(5846.66, 0) == "5 847"
    assert pdf_report._num(0.1, 2) == "0,10"
    assert pdf_report._pct(0.9999, 2) == "99,99 %"
    assert pdf_report._int(10001) == "10 001"


def test_text_is_made_safe_for_the_built_in_font():
    assert pdf_report._clean("a → b ✓ 🚨 é") == "a -> b OK  é"
    assert pdf_report._clean(None) == ""


# ------------------------------------------------------------ currency (TND)
def test_amounts_are_converted_to_dinars_at_the_configured_rate(monkeypatch):
    from config.settings import settings

    monkeypatch.setattr(settings, "display_currency", "USD")
    usd = asyncio.run(run_analysis(normal_count=30, seed=7))

    monkeypatch.setattr(settings, "display_currency", "TND")
    monkeypatch.setattr(settings, "usd_to_tnd_rate", 3.0)
    tnd = asyncio.run(run_analysis(normal_count=30, seed=7))

    assert usd["currency"]["code"] == "USD"
    assert tnd["currency"] == {"code": "TND", "symbol": "DT", "rate_from_usd": 3.0}

    for before, after in zip(usd["event_risks"], tnd["event_risks"]):
        assert after["annual_loss_expectancy"] == pytest.approx(
            before["annual_loss_expectancy"] * 3.0
        )
        assert after["value_at_risk_95"] == pytest.approx(before["value_at_risk_95"] * 3.0)
        # probabilities are not money: they must not be converted
        assert after["anomaly_probability"] == before["anomaly_probability"]

    assert public_view(tnd)["currency"]["symbol"] == "DT"


def test_pdf_shows_the_display_currency():
    analysis = _analysis()
    assert analysis["currency"]["code"] == "TND"

    assert pdf_report._money(1234) == "1 234 DT"
    # the symbol comes from the analysis, and does not leak between reports
    pdf = build_risk_report({**analysis, "currency": {"code": "USD", "symbol": "$", "rate_from_usd": 1.0}})
    assert pdf.startswith(b"%PDF")
    assert pdf_report._money(1234) == "1 234 DT"


# ------------------------------------------------------------ logo
def test_logo_is_a_transparent_png_shipped_with_the_dashboard():
    import os
    from PIL import Image

    path = os.path.normpath(pdf_report.LOGO_PATH)
    assert os.path.exists(path)
    with Image.open(path) as im:
        assert im.mode == "RGBA"
        assert im.getpixel((0, 0))[3] == 0  # corner is transparent, not white


def test_report_is_still_built_when_the_logo_is_missing(monkeypatch):
    monkeypatch.setattr(pdf_report, "LOGO_PATH", "/nonexistent/logo.png")

    assert pdf_report._logo() is None
    assert build_risk_report(_analysis()).startswith(b"%PDF")
