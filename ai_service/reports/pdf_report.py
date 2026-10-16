"""
PDF report of a LYNX risk analysis.

``build_risk_report(analysis)`` turns the dictionary produced by
``ai_service.risk.pipeline.run_analysis`` into a structured, printable PDF:

    1. Synthèse exécutive
    2. Méthodologie
    3. Test du chi-carré (résultat et lecture)
    4. Risque par événement (ALE, VaR, probabilités)
    5. Plan de traitement
    6. Kill chain
    7. Investigation (IOC, MITRE ATT&CK, chronologie)
    8. Hypothèses de chasse
    9. Recommandations et prochaines étapes
   10. Limites et lecture critique

Only reportlab's built-in Helvetica is used (no font files to ship), so every
text goes through ``_clean`` which keeps the characters Helvetica can draw
(Latin-1 accents, ², dashes) and replaces or drops the others (arrows,
emoji, Greek letters).
"""

import contextvars
import io
import logging
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    CondPageBreak,
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ai_service.mitre.knowledge_base import mitre_kb
from ai_service.risk.chi_square_tests import chi_square_tests

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------- theme
NAVY = colors.HexColor("#0b1220")
BLUE = colors.HexColor("#3b5bdb")
BLUE_SOFT = colors.HexColor("#e7ecff")
INK = colors.HexColor("#1b2433")
MUTED = colors.HexColor("#5b677a")
LINE = colors.HexColor("#d5dbe6")
ZEBRA = colors.HexColor("#f5f7fb")

PRIORITY_COLORS = {
    "critical": (colors.HexColor("#fde2e4"), colors.HexColor("#b4232c")),
    "high": (colors.HexColor("#fde2e4"), colors.HexColor("#b4232c")),
    "medium": (colors.HexColor("#fff1cc"), colors.HexColor("#8a6100")),
    "low": (colors.HexColor("#dcf5e7"), colors.HexColor("#1d7a49")),
}

PAGE_W, PAGE_H = A4
MARGIN = 1.8 * cm
CONTENT_W = PAGE_W - 2 * MARGIN

STAGES = [
    ("reconnaissance", "Reconnaissance"),
    ("exploitation", "Exploitation"),
    ("persistence", "Persistence"),
    ("lateral_movement", "Mouvement latéral"),
    ("exfiltration", "Exfiltration"),
]

STRATEGY_LABELS = {
    "REMEDIATE_URGENT": "Remédiation urgente",
    "REMEDIATE": "Remédiation",
    "MITIGATE": "Atténuation",
    "TRANSFER": "Transfert du risque",
    "ACCEPT": "Acceptation",
    "MONITOR": "Surveillance",
}


# ------------------------------------------------------------------ text utils
_REPLACEMENTS = {
    "→": "->",
    "≥": ">=",
    "≤": "<=",
    "≈": "~",
    "−": "-",
    "•": "-",
    "✓": "OK",
    "χ": "chi",
    " ": " ",
    " ": " ",
}


def _clean(value: Any) -> str:
    """Text safe for Helvetica (cp1252): replace known symbols, drop the rest."""
    text = "" if value is None else str(value)
    for old, new in _REPLACEMENTS.items():
        text = text.replace(old, new)
    return text.encode("cp1252", "ignore").decode("cp1252").strip()


def _p(value: Any) -> str:
    """Cleaned text, escaped for use inside a reportlab Paragraph."""
    return escape(_clean(value))


def _num(value: Any, decimals: int = 0) -> str:
    try:
        text = f"{float(value):,.{decimals}f}"
    except (TypeError, ValueError):
        return "-"
    return text.replace(",", " ").replace(".", ",")


_CURRENCY_SYMBOL = contextvars.ContextVar("lynx_currency_symbol", default="DT")


def _money(value: Any) -> str:
    text = _num(value, 0)
    return text if text == "-" else f"{text}\u00a0{_CURRENCY_SYMBOL.get()}"


def _pct(value: Any, decimals: int = 1) -> str:
    try:
        return _num(float(value) * 100, decimals) + " %"
    except (TypeError, ValueError):
        return "-"


def _p_value(value: Any) -> str:
    """p-values below the Monte-Carlo resolution are shown as '< 0,0001'."""
    try:
        p = float(value)
    except (TypeError, ValueError):
        return "-"
    if p < 1e-4:
        return "< 0,0001"
    return _num(p, 4)


def _int(value: Any) -> str:
    """Integer with a non-breaking space as thousands separator."""
    try:
        return f"{int(value):,}".replace(",", "\u00a0")
    except (TypeError, ValueError):
        return "-"


def _p_phrase(value: Any) -> str:
    """'p < 0,0001' / 'p = 0,0123' as a ready-to-read phrase."""
    text = _p_value(value)
    return f"p {text}" if text.startswith("<") else f"p = {text}"


METHOD_LABELS = {
    "asymptotic": "asymptotique (loi du chi-carré)",
    "monte_carlo": "simulation de Monte-Carlo (test exact)",
    "degenerate": "dégénérée (une seule catégorie)",
}

TIMELINE_LABELS = {
    "Immediately (< 4 hours)": "Immédiat (< 4 h)",
    "Within 24-48 hours": "Sous 24 à 48 h",
    "Within 1 week": "Sous 1 semaine",
    "Within 30 days": "Sous 30 jours",
    "Ongoing monitoring": "Surveillance continue",
}


def _timeline_label(value: Any) -> str:
    return TIMELINE_LABELS.get(str(value), _clean(value) or "-")


def _reduction(value: Any) -> str:
    """'85.0%' (engine format) -> '85,0 %'."""
    try:
        return _num(float(str(value).strip().rstrip("%")), 1) + "\u00a0%"
    except (TypeError, ValueError):
        return _clean(value)


def _reduction_value(value: Any) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return 0.0


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%d/%m/%Y %H:%M:%S")
    text = str(value or "")
    try:
        return datetime.fromisoformat(text).strftime("%d/%m/%Y %H:%M:%S")
    except ValueError:
        return text[:19].replace("T", " ") or "-"


def _priority_key(priority: Any) -> str:
    text = str(priority or "").lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    return "low"


def _strategy(label: Any) -> str:
    key = str(label or "").upper()
    return STRATEGY_LABELS.get(key, _clean(key.replace("_", " ").title()) or "-")


# ---------------------------------------------------------------------- styles
def _styles() -> Dict[str, ParagraphStyle]:
    base = dict(fontName="Helvetica", textColor=INK, alignment=TA_LEFT)
    return {
        "eyebrow": ParagraphStyle(
            "eyebrow", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
            textColor=colors.HexColor("#9db4ff"),
        ),
        "title": ParagraphStyle(
            "title", fontName="Helvetica-Bold", fontSize=21, leading=26,
            textColor=colors.white, spaceBefore=4, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName="Helvetica", fontSize=10, leading=14,
            textColor=colors.HexColor("#c4cee3"),
        ),
        "meta": ParagraphStyle(
            "meta", fontName="Helvetica", fontSize=8.5, leading=12,
            textColor=colors.HexColor("#c4cee3"),
        ),
        "h1": ParagraphStyle(
            "h1", fontName="Helvetica-Bold", fontSize=14, leading=18,
            textColor=NAVY, spaceBefore=16, spaceAfter=7,
        ),
        "h2": ParagraphStyle(
            "h2", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
            textColor=BLUE, spaceBefore=9, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9.3, leading=13.4, spaceAfter=5, **base
        ),
        "small": ParagraphStyle(
            "small", fontSize=8, leading=11, textColor=MUTED, spaceAfter=3,
            fontName="Helvetica",
        ),
        "bullet": ParagraphStyle(
            "bullet", fontSize=9.2, leading=13, leftIndent=12,
            bulletIndent=2, spaceAfter=2.5, **base
        ),
        "cell": ParagraphStyle(
            "cell", fontSize=8, leading=10.4, **base
        ),
        "cellb": ParagraphStyle(
            "cellb", fontName="Helvetica-Bold", fontSize=8, leading=10.4,
            textColor=INK,
        ),
        "head": ParagraphStyle(
            "head", fontName="Helvetica-Bold", fontSize=7.8, leading=10,
            textColor=colors.white,
        ),
        "code": ParagraphStyle(
            "code", fontName="Courier", fontSize=7.4, leading=9.6,
            textColor=colors.HexColor("#2d3748"), backColor=ZEBRA,
            borderPadding=(3, 4, 3, 4), spaceBefore=2, spaceAfter=5,
        ),
        "kpi_value": ParagraphStyle(
            "kpi_value", fontName="Helvetica-Bold", fontSize=15, leading=18,
            textColor=NAVY,
        ),
        "kpi_label": ParagraphStyle(
            "kpi_label", fontName="Helvetica", fontSize=7.8, leading=10,
            textColor=MUTED,
        ),
        "box": ParagraphStyle(
            "box", fontSize=9.3, leading=13.4, **base
        ),
    }


# ---------------------------------------------------------------- building blocks
def _table(
    rows: Sequence[Sequence[Any]],
    widths: Sequence[float],
    st: Dict[str, ParagraphStyle],
    header: bool = True,
    first_col_bold: bool = False,
    extra: Optional[Iterable[tuple]] = None,
    repeat: int = 1,
) -> Table:
    """Table with wrapped cells, zebra rows and a coloured header row."""
    data: List[List[Any]] = []
    for r, row in enumerate(rows):
        cells = []
        for c, cell in enumerate(row):
            if isinstance(cell, str):
                if header and r == 0:
                    style = st["head"]
                elif first_col_bold and c == 0:
                    style = st["cellb"]
                else:
                    style = st["cell"]
                cells.append(Paragraph(_p(cell), style))
            else:
                cells.append(cell)
        data.append(cells)

    table = Table(
        data,
        colWidths=list(widths),
        repeatRows=repeat if header else 0,
        hAlign="LEFT",
    )
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
        for i in range(1, len(data)):
            if i % 2 == 0:
                commands.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    if extra:
        commands.extend(extra)
    table.setStyle(TableStyle(commands))
    return table


def _priority_cell(priority: Any, st: Dict[str, ParagraphStyle]) -> Paragraph:
    _, fg = PRIORITY_COLORS[_priority_key(priority)]
    style = ParagraphStyle(
        "prio", parent=st["cellb"], textColor=fg,
    )
    return Paragraph(_p(priority or "-"), style)


def _priority_background(rows_priority: Sequence[Any], column: int) -> List[tuple]:
    commands = []
    for index, priority in enumerate(rows_priority, start=1):
        bg, _ = PRIORITY_COLORS[_priority_key(priority)]
        commands.append(("BACKGROUND", (column, index), (column, index), bg))
    return commands


def _bullets(items: Iterable[Any], st: Dict[str, ParagraphStyle]) -> List[Paragraph]:
    return [
        Paragraph(_p(item), st["bullet"], bulletText="-")
        for item in items
        if _clean(item)
    ]


def _callout(text_html: str, st: Dict[str, ParagraphStyle]) -> Table:
    box = Table(
        [[Paragraph(text_html, st["box"])]],
        colWidths=[CONTENT_W],
        hAlign="LEFT",
    )
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BLUE_SOFT),
                ("LINEBEFORE", (0, 0), (0, -1), 3, BLUE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return box


def _bar_chart(
    title: str,
    rows: Sequence[tuple],
    formatter,
    st: Dict[str, ParagraphStyle],
    max_value: Optional[float] = None,
) -> KeepTogether:
    """Horizontal bar chart drawn with plain shapes: (label, value) rows."""
    row_h = 15
    label_w = 150
    value_w = 78
    bar_w = CONTENT_W - label_w - value_w - 6
    height = row_h * max(len(rows), 1) + 6
    drawing = Drawing(CONTENT_W, height)

    top = max_value if max_value else max((v for _, v in rows), default=0) or 1.0

    for index, (label, value) in enumerate(rows):
        y = height - (index + 1) * row_h
        drawing.add(
            String(0, y + 4, _clean(label)[:34], fontName="Helvetica",
                   fontSize=7.6, fillColor=INK)
        )
        drawing.add(
            Rect(label_w, y + 2, bar_w, 8, fillColor=ZEBRA, strokeColor=None)
        )
        width = max(0.0, min(1.0, float(value) / top)) * bar_w
        if width > 0:
            drawing.add(
                Rect(label_w, y + 2, width, 8, fillColor=BLUE, strokeColor=None)
            )
        drawing.add(
            String(label_w + bar_w + 6, y + 3, _clean(formatter(value)),
                   fontName="Helvetica-Bold", fontSize=7.6, fillColor=NAVY)
        )

    return KeepTogether([Paragraph(_p(title), st["h2"]), drawing, Spacer(1, 4)])


# ------------------------------------------------------------------ page chrome
class _NumberedCanvas(canvas.Canvas):
    """Canvas that knows the total page count ("Page 2 / 8")."""

    footer_text = "LYNX"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages: List[Dict[str, Any]] = []

    def showPage(self):
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self._draw_chrome(total)
            super().showPage()
        super().save()

    def _draw_chrome(self, total: int) -> None:
        self.saveState()
        self.setStrokeColor(LINE)
        self.setLineWidth(0.5)
        self.line(MARGIN, 1.35 * cm, PAGE_W - MARGIN, 1.35 * cm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, 0.9 * cm, _clean(self.footer_text))
        self.drawRightString(
            PAGE_W - MARGIN, 0.9 * cm, f"Page {self._pageNumber} / {total}"
        )
        self.restoreState()


# ------------------------------------------------------------------- sections
LOGO_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "dashboard", "assets", "lynx-logo.png"
)


def _logo(height: float = 3.1 * cm) -> Optional[Image]:
    """The LYNX logo (transparent PNG) scaled to ``height``; None if the file is missing."""
    path = os.path.normpath(LOGO_PATH)
    if not os.path.exists(path):
        return None
    try:
        from PIL import Image as PILImage

        with PILImage.open(path) as im:
            ratio = im.width / im.height
        return Image(path, width=height * ratio, height=height, mask="auto")
    except Exception:  # a broken logo must never break the report
        logger.warning("LYNX logo could not be loaded: %s", path)
        return None


def _tef_text(model: Dict[str, Any]) -> str:
    if model.get("tef_mode") == "observed":
        return ("<b>Fréquence des menaces (TEF).</b> Mesurée sur la fenêtre analysée : somme des "
                "probabilités d'anomalie des événements de la catégorie, ramenée à l'année en "
                f"supposant que la fenêtre représente {_p(_num(model.get('observation_days'), 0))} "
                "jours d'activité (365 = les événements observés sont comptés comme ceux d'une "
                "année), puis pondérée par la catégorie de menace. Elle n'est jamais inférieure "
                "à l'estimation a priori. Cette durée est une hypothèse réglable.")
    return ("<b>Fréquence des menaces (TEF).</b> Estimation a priori : 0,01 événement par an, "
            "multipliée par la catégorie de menace et par la probabilité d'anomalie. "
            "Hypothèse de démonstration, non mesurée.")


def _source_line(source: Dict[str, Any]) -> str:
    """One line saying whether the figures come from real sensors or from simulation."""
    line = str(source.get("label") or "")
    if source.get("is_real"):
        line += (f" · {source.get('analysed_events', '?')} événement(s) analysé(s) sur "
                 f"{source.get('window_hours', '?')} h · baseline de "
                 f"{source.get('baseline_events', '?')} événement(s)")
    else:
        line += " (événements générés, non issus d'un système réel)"
    return line


def _cover(analysis: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> Table:
    params = analysis.get("parameters") or {}
    seed = params.get("seed")
    generated = _timestamp(analysis.get("generated_at"))

    meta = (
        f"Généré le {_p(generated)} (UTC) &nbsp;|&nbsp; "
        f"Analyse {_p(analysis.get('analysis_id'))} &nbsp;|&nbsp; "
        f"Baseline : {_p(params.get('normal_count', '-'))} événements normaux &nbsp;|&nbsp; "
        f"Graine : {_p(seed if seed is not None else 'aléatoire')}"
    )
    source = analysis.get("data_source") or {}
    if source.get("label"):
        meta += f"<br/>Source des données : <b>{_p(_source_line(source))}</b>"

    logo = _logo()
    logo_w = (logo.drawWidth + 0.6 * cm) if logo else 0
    text_w = CONTENT_W - logo_w

    title_block = Table(
        [
            [Paragraph("LYNX &nbsp;·&nbsp; PROBABILISTIC THREAT HUNTING", st["eyebrow"])],
            [Paragraph("Rapport d'analyse de risque<br/>et d'investigation", st["title"])],
            [Paragraph(
                "Détection comportementale, quantification FAIR du risque "
                "et aide à la décision.", st["subtitle"])],
        ],
        colWidths=[text_w],
        hAlign="LEFT",
    )
    title_block.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]
        )
    )

    block = Table(
        [
            [title_block, logo or ""],
            [Paragraph(meta, st["meta"]), ""],
        ],
        colWidths=[text_w, logo_w] if logo else [CONTENT_W, 0],
        hAlign="LEFT",
    )
    block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("SPAN", (0, 1), (-1, 1)),
                ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                ("TOPPADDING", (0, 0), (-1, 0), 16),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 1), (-1, 1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
            ]
        )
    )
    return block


def _top_event(analysis: Dict[str, Any]) -> Optional[int]:
    rows = analysis.get("event_risks") or []
    if not rows:
        return None
    return max(
        range(len(rows)),
        key=lambda i: rows[i].get("annual_loss_expectancy") or 0,
    )


def _section_summary(analysis, st) -> List[Any]:
    story: List[Any] = [Paragraph("1. Synthèse exécutive", st["h1"])]

    rows = analysis.get("event_risks") or []
    chi = analysis.get("chi_square") or {}
    top_index = _top_event(analysis)
    top = rows[top_index] if top_index is not None else None
    detail = (analysis.get("event_details") or [{}] * len(rows))[top_index] if top else {}

    def kpi(value: str, label: str) -> Table:
        cell = Table(
            [[Paragraph(_p(value), st["kpi_value"])],
             [Paragraph(_p(label), st["kpi_label"])]],
            colWidths=[CONTENT_W / 4 - 6],
        )
        cell.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
                ]
            )
        )
        return cell

    kpis = Table(
        [[
            kpi(str(len(analysis.get("events") or [])), "Événements du scénario"),
            kpi(str(len(analysis.get("attacks") or [])), "Attaque(s) corrélée(s)"),
            kpi(_money(top.get("annual_loss_expectancy")) if top else "-",
                "Perte annuelle attendue max. (ALE)"),
            kpi(_p_value(chi.get("p_value")), "p-value du test chi-carré"),
        ]],
        colWidths=[CONTENT_W / 4] * 4,
        hAlign="LEFT",
    )
    kpis.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
    story += [kpis, Spacer(1, 8)]

    if chi.get("is_significant") is not None:
        verdict = (
            "s'écarte de façon significative de la baseline"
            if chi.get("is_significant")
            else "ne s'écarte pas de façon significative de la baseline"
        )
        story.append(
            Paragraph(
                f"Le scénario analysé comporte <b>{len(analysis.get('events') or [])} "
                f"événements</b>. Le test du chi-carré montre que leur distribution "
                f"par type {_p(verdict)} ({_p(_p_phrase(chi.get('p_value')))}, "
                f"méthode : {_p(METHOD_LABELS.get(chi.get('method'), chi.get('method')))}). "
                f"Corrélation sur la kill chain : "
                f"{len(analysis.get('attacks') or [])} attaque(s) reconstituée(s).",
                st["body"],
            )
        )

    if top:
        controls = (detail or {}).get("recommended_controls") or top.get(
            "recommended_controls") or []
        html = (
            f"<b>Décision recommandée : {_p(_strategy(top.get('strategy')))} "
            f"(priorité {_p(top.get('priority'))})</b><br/>"
            f"Événement le plus exposé : <b>{_p(top.get('event'))}</b> "
            f"(utilisateur {_p(top.get('user') or '-')}). "
            f"ALE : {_p(_money(top.get('annual_loss_expectancy')))} ; "
            f"VaR 95 % : {_p(_money(top.get('value_at_risk_95')))} ; "
            f"VaR 99 % : {_p(_money(top.get('value_at_risk_99')))}."
        )
        if detail.get("implementation_timeline"):
            html += (
                f"<br/>Délai de mise en oeuvre : "
                f"{_p(_timeline_label(detail['implementation_timeline']))}."
            )
        story.append(_callout(html, st))
        if controls:
            story += [Paragraph("Contrôles prioritaires", st["h2"])]
            story += _bullets(controls[:4], st)

    return story


def _currency_sentence(analysis: Dict[str, Any]) -> str:
    cur = analysis.get("currency") or {}
    if not cur or cur.get("code") == "USD":
        return " Montants exprimés en dollars américains."
    return (
        f" Montants exprimés en {_clean(cur.get('code'))} ({_clean(cur.get('symbol'))}) : "
        f"le moteur valorise les pertes en dollars américains, convertis au taux de "
        f"1 USD = {_num(cur.get('rate_from_usd'), 4)} {_clean(cur.get('symbol'))}."
    )


def _section_method(analysis, st) -> List[Any]:
    sims = getattr(chi_square_tests, "n_simulations", 10000)
    alpha = getattr(chi_square_tests, "p_value_threshold", 0.05)
    return [
        Paragraph("2. Méthodologie", st["h1"]),
        Paragraph(_tef_text(analysis.get("risk_model") or {}), st["body"]),
        Paragraph(
            "<b>Origine des données.</b> " + _p(_source_line(analysis.get("data_source") or {}))
            + ". " + ("Les alertes proviennent de capteurs de sécurité réels."
                      if (analysis.get("data_source") or {}).get("is_real")
                      else "Les chiffres illustrent la méthode et ne décrivent pas un système réel."),
            st["body"]),
        Paragraph(
            "<b>Baseline.</b> Un profil de comportement normal est construit à partir "
            "d'événements de référence (heures d'activité, processus, ports, types "
            "d'événements, sévérités). Il sert de référence à toutes les mesures.",
            st["body"]),
        Paragraph(
            "<b>Probabilité d'anomalie.</b> Chaque événement reçoit une probabilité "
            "continue qui combine l'écart temporel, l'écart de processus, l'écart "
            "réseau et la rareté du type d'événement. Elle sert à hiérarchiser les "
            "événements ; la décision binaire « anomalie / normal » reste celle du "
            "modèle d'apprentissage.", st["body"]),
        Paragraph(
            "<b>Test du chi-carré.</b> H0 : la fenêtre observée provient de la "
            "distribution de la baseline. Les effectifs de la baseline sont lissés "
            "(Lidstone) pour qu'une catégorie jamais vue garde une probabilité faible "
            "mais non nulle. La statistique de Pearson X2 = somme (O - E)2 / E est "
            "calculée sur l'union des catégories. Si tous les effectifs attendus sont "
            f">= 5, la p-value suit la loi du chi-carré (ddl = K - 1) ; sinon elle est "
            f"estimée par un test multinomial exact par simulation "
            f"({_int(sims)} tirages)."
            + f" Seuil de décision : alpha = {_num(alpha, 2)}. Le score affiché "
            "« 1 - p » mesure la force de la preuve contre H0 ; ce n'est pas une "
            "probabilité calibrée d'attaque.", st["body"]),
        Paragraph(
            "<b>Quantification FAIR.</b> Pour chaque événement, la fréquence "
            "d'événement de menace et la vulnérabilité donnent la fréquence "
            "d'événement de perte ; elle est combinée à l'amplitude de perte probable "
            "dans une simulation de Monte Carlo. On en déduit la perte annuelle "
            "attendue (ALE), la valeur à risque à 95 % et 99 % (VaR) et la perte "
            "moyenne au-delà de la VaR 95 % (expected shortfall)." + _currency_sentence(analysis),
            st["body"]),
        Paragraph(
            "<b>Kill chain et investigation.</b> Les événements sont classés par étape "
            "(reconnaissance, exploitation, persistence, mouvement latéral, "
            "exfiltration), chaînés par continuité de source et de destination, puis "
            "rattachés aux techniques MITRE ATT&amp;CK.", st["body"]),
    ]


def _section_chi(analysis, st) -> List[Any]:
    chi = analysis.get("chi_square") or {}
    story: List[Any] = [CondPageBreak(7 * cm),
                        Paragraph("3. Test du chi-carré sur le scénario", st["h1"])]

    if not chi or chi.get("test") in (None, "no_data", "no_baseline"):
        story.append(Paragraph(
            "Le test n'a pas pu être calculé (données ou baseline insuffisantes).",
            st["body"]))
        return story

    decision = "H0 rejetée" if chi.get("is_significant") else "H0 non rejetée"
    rows = [
        ["Indicateur", "Valeur", "Lecture"],
        ["Statistique X2", _num(chi.get("chi2_statistic"), 2),
         "Écart global entre observé et attendu"],
        ["Degrés de liberté", str(chi.get("degrees_of_freedom", "-")),
         "Nombre de catégories - 1"],
        ["p-value", _p_value(chi.get("p_value")),
         f"Seuil alpha = {_num(chi.get('p_value_threshold'), 2)}"],
        ["Méthode de calcul",
         METHOD_LABELS.get(chi.get("method"), _clean(chi.get("method"))),
         "Asymptotique si effectifs attendus >= 5, sinon Monte-Carlo"],
        ["Effectif attendu minimum", _num(chi.get("min_expected_count"), 2),
         "Règle de validité : >= 5"],
        ["Taille d'effet (w de Cohen)", _num(chi.get("cohens_w"), 2),
         "0,5 et plus : effet fort"],
        ["Événements observés", str(chi.get("n_observed", "-")),
         "Taille de la fenêtre testée"],
        ["Décision", decision, f"Score 1 - p = {_pct(chi.get('anomaly_probability'), 2)}"],
    ]
    story.append(_table(rows, [4.6 * cm, 3.6 * cm, CONTENT_W - 8.2 * cm], st,
                        first_col_bold=True))
    story.append(Spacer(1, 6))

    new = chi.get("new_categories") or []
    reading = (
        "La distribution des types d'événements du scénario "
        + ("s'écarte nettement de celle de la baseline." if chi.get("is_significant")
           else "est compatible avec celle de la baseline.")
    )
    if new:
        reading += (
            " Types d'événements jamais observés dans la baseline : "
            f"{', '.join(map(str, new))}."
        )
    if chi.get("method") == "monte_carlo":
        sims = getattr(chi_square_tests, "n_simulations", 10000)
        reading += (
            f" Les effectifs attendus sont faibles (minimum "
            f"{_num(chi.get('min_expected_count'), 2)}) : la loi asymptotique n'est "
            f"pas fiable, la p-value vient donc d'une simulation exacte. Avec "
            f"{_int(sims)} tirages la plus petite p-value possible est "
            f"1/{_int(sims + 1)}, d'où l'affichage « < 0,0001 »."
        )
    story.append(_callout(_p(reading), st))

    # observed vs baseline
    baseline_types = (analysis.get("baseline") or {}).get("event_types") or {}
    observed = chi.get("observed_counts") or {}
    categories = list(baseline_types) + [c for c in observed if c not in baseline_types]
    b_total = sum(baseline_types.values()) or 1
    o_total = sum(observed.values()) or 1

    table_rows = [["Type d'événement", "Baseline (n)", "Baseline (%)",
                   "Observé (n)", "Observé (%)", "Statut"]]
    for category in categories:
        b = baseline_types.get(category, 0)
        o = observed.get(category, 0)
        table_rows.append([
            category.replace("_", " "), str(b), _pct(b / b_total, 1),
            str(o), _pct(o / o_total, 1),
            "Nouvelle" if category in new else "Connue",
        ])
    story += [
        Paragraph("Distribution observée et baseline", st["h2"]),
        _table(table_rows,
               [4.4 * cm, 2.4 * cm, 2.5 * cm, 2.4 * cm, 2.5 * cm,
                CONTENT_W - 14.2 * cm],
               st, first_col_bold=True),
    ]
    return story


def _section_events(analysis, st) -> List[Any]:
    rows = analysis.get("event_risks") or []
    story: List[Any] = [CondPageBreak(8 * cm),
                        Paragraph("4. Risque par événement", st["h1"])]
    if not rows:
        story.append(Paragraph("Aucun événement analysé.", st["body"]))
        return story

    table_rows = [["#", "Événement", "Utilisateur", "Anomalie", "ALE",
                   "VaR 95 %", "VaR 99 %", "Priorité"]]
    for i, r in enumerate(rows, start=1):
        table_rows.append([
            str(i), _clean(r.get("event")).replace("_", " "),
            _clean(r.get("user") or "-"),
            _pct(r.get("anomaly_probability")),
            _money(r.get("annual_loss_expectancy")),
            _money(r.get("value_at_risk_95")),
            _money(r.get("value_at_risk_99")),
            _priority_cell(r.get("priority"), st),
        ])
    widths = [0.7 * cm, 3.2 * cm, 2.6 * cm, 1.9 * cm, 2.1 * cm, 2.3 * cm, 2.3 * cm]
    widths.append(CONTENT_W - sum(widths))
    story.append(_table(
        table_rows, widths, st,
        extra=_priority_background([r.get("priority") for r in rows], 7)))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "L'ALE est une espérance annuelle ; la VaR est la perte qui n'est dépassée "
        "que dans 5 % (VaR 95 %) ou 1 % (VaR 99 %) des simulations.", st["small"]))

    labels = [f"{i}. {_clean(r.get('event')).replace('_', ' ')}"
              for i, r in enumerate(rows, start=1)]
    story.append(_bar_chart(
        "Perte annuelle attendue (ALE) par événement",
        [(l, r.get("annual_loss_expectancy") or 0) for l, r in zip(labels, rows)],
        _money, st))
    story.append(_bar_chart(
        "Probabilité d'anomalie par événement",
        [(l, r.get("anomaly_probability") or 0) for l, r in zip(labels, rows)],
        _pct, st, max_value=1.0))
    return story


def _section_treatment(analysis, st) -> List[Any]:
    rows = analysis.get("event_risks") or []
    details = analysis.get("event_details") or []
    story: List[Any] = [CondPageBreak(7 * cm),
                        Paragraph("5. Plan de traitement du risque", st["h1"])]
    if not rows:
        story.append(Paragraph("Aucun traitement à proposer.", st["body"]))
        return story

    table_rows = [["#", "Événement", "Stratégie", "Délai", "ALE cible",
                   "Contrôles recommandés"]]
    for i, r in enumerate(rows):
        d = details[i] if i < len(details) else {}
        controls = d.get("recommended_controls") or r.get("recommended_controls") or []
        table_rows.append([
            str(i + 1), _clean(r.get("event")).replace("_", " "),
            _strategy(r.get("strategy")),
            _timeline_label(d.get("implementation_timeline")),
            (_money(d.get("target_ale")) + (
                f" (-{_reduction(d.get('risk_reduction_target'))})"
                if _reduction_value(d.get("risk_reduction_target")) > 0 else ""))
            if d.get("target_ale") else "-",
            "; ".join(_clean(c) for c in controls[:3]) or "-",
        ])
    widths = [0.7 * cm, 2.7 * cm, 2.6 * cm, 2.6 * cm, 2.6 * cm]
    widths.append(CONTENT_W - sum(widths))
    story.append(_table(table_rows, widths, st))
    return story


def _stage_counts(attacks: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    seen: Dict[str, List[str]] = {key: [] for key, _ in STAGES}
    for attack in attacks:
        for event in attack.get("events") or []:
            stage = event.get("kill_chain_stage")
            if stage in seen:
                seen[stage].append(str(event.get("event_type")))
    return seen


def _section_killchain(analysis, st) -> List[Any]:
    attacks = analysis.get("attacks") or []
    story: List[Any] = [CondPageBreak(7 * cm),
                        Paragraph("6. Kill chain", st["h1"])]
    if not attacks:
        story.append(Paragraph("Aucune attaque corrélée dans ce scénario.", st["body"]))
        return story

    seen = _stage_counts(attacks)
    rows = [["Étape", "Statut", "Événements", "Types observés"]]
    extra = []
    for index, (key, label) in enumerate(STAGES, start=1):
        events = seen[key]
        rows.append([
            f"{index}. {label}",
            "Observée" if events else "Non observée",
            str(len(events)),
            ", ".join(sorted(set(t.replace('_', ' ') for t in events))) or "-",
        ])
        if events:
            extra.append(("BACKGROUND", (0, index), (-1, index), BLUE_SOFT))
    story.append(_table(rows, [4.2 * cm, 3 * cm, 2.4 * cm, CONTENT_W - 9.6 * cm],
                        st, first_col_bold=True, extra=extra))
    observed = sum(1 for key, _ in STAGES if seen[key])
    story += [Spacer(1, 4),
              Paragraph(f"{observed} étape(s) sur 5 observée(s) dans le scénario.",
                        st["small"])]
    return story


def _technique_labels(ids: Optional[Iterable[str]]) -> str:
    """'T1046 (Network Service Discovery), T1018 (...)' using the ATT&CK catalogue."""
    labels = []
    for technique_id in ids or []:
        name = mitre_kb.name(technique_id)
        labels.append(f"{technique_id} ({name})" if name else str(technique_id))
    return ", ".join(labels) or "-"


def _list_or_dash(values: Iterable[Any], limit: int = 8) -> str:
    items = [_clean(v) for v in values if _clean(v)]
    if not items:
        return "-"
    text = ", ".join(items[:limit])
    return text + (f" (+{len(items) - limit})" if len(items) > limit else "")


def _section_investigation(analysis, st) -> List[Any]:
    reports = analysis.get("reports") or []
    story: List[Any] = [CondPageBreak(8 * cm),
                        Paragraph("7. Investigation", st["h1"])]
    if not reports:
        story.append(Paragraph("Aucun rapport d'investigation généré.", st["body"]))
        return story

    for number, report in enumerate(reports, start=1):
        summary = report.get("attack_summary") or {}
        iocs = report.get("indicators_of_compromise") or {}
        story.append(Paragraph(
            f"Attaque {_p(summary.get('attack_id'))}", st["h2"]))

        facts = [
            ["Source", _clean(summary.get("source_ip")),
             "Gravité", _clean(summary.get("severity"))],
            ["Confiance", _pct(summary.get("confidence")),
             "Événements", str(summary.get("event_count", "-"))],
            ["Durée", f"{_num(summary.get('time_span_minutes'), 0)} min",
             "Statut", _clean(summary.get("status"))],
            ["Hôtes affectés", _list_or_dash(summary.get("affected_hosts") or []),
             "Utilisateurs affectés",
             _list_or_dash(summary.get("affected_users") or [])],
            ["Premier événement", _timestamp(summary.get("first_event")),
             "Dernier événement", _timestamp(summary.get("last_event"))],
        ]
        story.append(_table(
            facts, [3 * cm, 5.5 * cm, 3.4 * cm, CONTENT_W - 11.9 * cm], st,
            header=False,
            extra=[("BACKGROUND", (0, 0), (0, -1), ZEBRA),
                   ("BACKGROUND", (2, 0), (2, -1), ZEBRA)]))

        narrative = (report.get("kill_chain") or {}).get("narrative")
        if narrative:
            story += [Spacer(1, 6), _callout(_p(narrative), st)]

        ioc_rows = [["Indicateur", "Nombre", "Valeurs (extrait)"]]
        for key, label in (("ips", "Adresses IP"), ("domains", "Domaines"),
                           ("file_hashes", "Hashes de fichiers"),
                           ("process_names", "Processus"),
                           ("file_paths", "Chemins de fichiers")):
            values = iocs.get(key) or []
            ioc_rows.append([label, str(len(values)), _list_or_dash(values, 6)])
        story += [
            Paragraph("Indicateurs de compromission (IOC)", st["h2"]),
            _table(ioc_rows, [4 * cm, 2 * cm, CONTENT_W - 6 * cm], st,
                   first_col_bold=True),
        ]

        techniques = report.get("mitre_attack_mapping") or []
        story.append(Paragraph("Techniques MITRE ATT&amp;CK", st["h2"]))
        if techniques:
            rows = [["Technique", "Nom", "Tactique(s) ATT&CK", "Événement(s)", "Pertinence"]]
            for t in techniques:
                terms = ", ".join(t.get("matched_terms") or [])
                rows.append([
                    _clean(t.get("technique_id")),
                    _clean(t.get("name") or t.get("description")),
                    _clean(", ".join(t.get("tactics") or [])) or "-",
                    _clean(", ".join(
                        e.replace("_", " ") for e in (t.get("event_types") or [t.get("event_type", "")])
                    )),
                    f"{_num(t.get('score'), 1)}" + (f" ({terms})" if terms else ""),
                ])
            story.append(_table(
                rows, [2.0 * cm, 3.9 * cm, 3.3 * cm, 2.8 * cm, CONTENT_W - 12.0 * cm], st,
                first_col_bold=True))
            sources = sorted({_clean(t.get("source")) for t in techniques if t.get("source")})
            story.append(Paragraph(
                "Source : " + _p(", ".join(sources) or "-") + ". Correspondance automatique : "
                "chaque événement est recherché dans le catalogue ATT&amp;CK (nom des techniques "
                "pondéré trois fois plus que leur description), restreint aux tactiques "
                "compatibles avec son étape de kill chain. La pertinence est un score de "
                "recherche, pas une probabilité ; la correspondance reste à valider par un analyste.",
                st["small"]))
        else:
            story.append(Paragraph("Aucune technique MITRE corrélée.", st["body"]))

        timeline = report.get("timeline") or []
        story.append(Paragraph("Chronologie", st["h2"]))
        if timeline:
            rows = [["#", "Horodatage", "Événement", "Acteur / hôte", "Gravité"]]
            for item in timeline:
                description = _clean(item.get("description") or "")
                description = description.replace(" by None", "")
                rows.append([
                    str(item.get("sequence", "")),
                    _timestamp(item.get("timestamp")),
                    _clean(item.get("event_type")).replace("_", " "),
                    description.replace("_", " ") or "-",
                    _clean(item.get("severity") or "-"),
                ])
            story.append(_table(
                rows, [0.8 * cm, 3.5 * cm, 3.3 * cm, CONTENT_W - 9.1 * cm, 1.5 * cm],
                st))
        else:
            story.append(Paragraph("Aucun événement dans la chronologie.", st["body"]))
    return story


def _section_hypotheses(analysis, st) -> List[Any]:
    hypotheses = analysis.get("hypotheses") or []
    story: List[Any] = [CondPageBreak(8 * cm),
                        Paragraph("8. Hypothèses de chasse", st["h1"])]
    if not hypotheses:
        story.append(Paragraph("Aucune hypothèse générée.", st["body"]))
        return story

    story.append(Paragraph(
        f"{len(hypotheses)} hypothèse(s) à vérifier par les analystes, rattachées aux "
        "étapes de la kill chain et aux techniques MITRE ATT&amp;CK.", st["body"]))

    for index, h in enumerate(hypotheses, start=1):
        block: List[Any] = [
            Paragraph(
                f"H{index}. {_p(h.get('title'))} "
                f"<font color='#5b677a' size='8'>({_p(_clean(h.get('stage')).replace('_', ' '))}"
                f" · confiance {_p(_pct(h.get('confidence'), 0))}"
                f" · MITRE {_p(_technique_labels(h.get('mitre_techniques')))})</font>",
                st["cellb"]),
            Paragraph(_p(h.get("description")), st["body"]),
        ]
        indicators = h.get("indicators") or []
        if indicators:
            block.append(Paragraph(
                "<b>Indicateurs :</b> " + _p("; ".join(map(str, indicators))),
                st["small"]))
        for query in (h.get("suggested_queries") or [])[:2]:
            block.append(Paragraph(
                f"<b>{_p(query.get('name'))}</b>", st["small"]))
            block.append(Paragraph(_p(query.get("query")), st["code"]))
        block.append(Spacer(1, 3))
        story.append(KeepTogether(block))
    return story


def _section_recommendations(analysis, st) -> List[Any]:
    story: List[Any] = [CondPageBreak(7 * cm),
                        Paragraph("9. Recommandations et prochaines étapes", st["h1"])]
    reports = analysis.get("reports") or []

    recommendations: List[str] = []
    next_steps: List[str] = []
    for report in reports:
        for item in report.get("recommendations") or []:
            if _clean(item) and _clean(item) not in recommendations:
                recommendations.append(_clean(item))
        for item in report.get("next_steps") or []:
            if _clean(item) and _clean(item) not in next_steps:
                next_steps.append(_clean(item))

    story.append(Paragraph("Recommandations issues de l'investigation", st["h2"]))
    story += _bullets(recommendations, st) or [
        Paragraph("Maintenir la surveillance et compléter l'analyse.", st["body"])]

    if next_steps:
        story.append(Paragraph("Prochaines étapes", st["h2"]))
        story += _bullets(
            [s.split(". ", 1)[1] if s[:1].isdigit() and ". " in s else s
             for s in next_steps], st)
    return story


def _section_limits(analysis, st) -> List[Any]:
    chi = analysis.get("chi_square") or {}
    n = chi.get("n_observed")
    limits = [
        "Les événements proviennent de connecteurs simulés (Wazuh, enrichissement) : "
        "les chiffres illustrent la méthode, ils ne décrivent pas une organisation réelle.",
        "La baseline repose sur un échantillon réduit "
        f"({(analysis.get('baseline') or {}).get('event_count', '-')} événements) ; "
        "une baseline plus longue rendrait les fréquences attendues plus stables.",
        "Le test du chi-carré porte sur une fenêtre courte"
        + (f" ({n} événements)" if n else "")
        + " : la puissance statistique est limitée et la p-value est estimée par "
        "simulation lorsque les effectifs attendus sont faibles.",
        "Le score « 1 - p » exprime la force de la preuve contre H0 ; il ne doit pas "
        "être lu comme une probabilité d'attaque.",
        "La correspondance événement -> technique MITRE ATT&CK est automatique "
        "(recherche dans le catalogue officiel) : c'est une aide à l'investigation, "
        "à valider par un analyste, pas une attribution certaine.",
        "Le taux de change est fixe (paramètre de configuration), non actualisé "
        "automatiquement : il doit être aligné sur le taux de la Banque centrale.",
        "Les paramètres FAIR (fréquences, vulnérabilité, amplitude de perte) sont des "
        "valeurs par défaut non calibrées sur le contexte métier : l'ALE et la VaR "
        "sont des ordres de grandeur pour prioriser, pas des montants budgétaires.",
    ]
    story: List[Any] = [CondPageBreak(6 * cm),
                        Paragraph("10. Limites et lecture critique", st["h1"])]
    story += _bullets(limits, st)
    return story


# ------------------------------------------------------------------ entry point
def _render(analysis: Dict[str, Any]) -> bytes:
    """Render the analysis as a PDF and return its bytes."""
    st = _styles()
    buffer = io.BytesIO()

    class Canvas(_NumberedCanvas):
        footer_text = (
            f"LYNX · Rapport d'analyse de risque · analyse "
            f"{analysis.get('analysis_id', '-')}"
        )

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=1.6 * cm,
        bottomMargin=1.9 * cm,
        title="LYNX - Rapport d'analyse de risque et d'investigation",
        author="LYNX Probabilistic Threat Hunting",
        subject=f"Analyse {analysis.get('analysis_id', '')}",
    )

    story: List[Any] = [_cover(analysis, st), Spacer(1, 6)]
    for section in (
        lambda: _section_summary(analysis, st),
        lambda: _section_method(analysis, st),
        lambda: _section_chi(analysis, st),
        lambda: _section_events(analysis, st),
        lambda: _section_treatment(analysis, st),
        lambda: _section_killchain(analysis, st),
        lambda: _section_investigation(analysis, st),
        lambda: _section_hypotheses(analysis, st),
        lambda: _section_recommendations(analysis, st),
        lambda: _section_limits(analysis, st),
    ):
        story += section()

    document.build(story, canvasmaker=Canvas)
    return buffer.getvalue()



def build_risk_report(analysis: Dict[str, Any]) -> bytes:
    """Render the analysis as a PDF and return its bytes."""
    symbol = _clean((analysis.get("currency") or {}).get("symbol") or "DT")
    token = _CURRENCY_SYMBOL.set(symbol)
    try:
        return _render(analysis)
    finally:
        _CURRENCY_SYMBOL.reset(token)
