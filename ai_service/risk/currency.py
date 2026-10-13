"""
Display currency of the risk figures.

The FAIR engine prices losses in US dollars (its default loss magnitudes are
USD figures). Everything shown to the analyst (API, dashboard, PDF) is
converted once, at the output boundary of the pipeline, so the engine itself
never has to know about the display currency.

Configuration (environment variables or ``config/.env``):

* ``DISPLAY_CURRENCY``  : ``TND`` (default, Tunisian dinar) or ``USD``
* ``USD_TO_TND_RATE``   : dinars for 1 US dollar (default 2.9927, 12/10/2026).
                          Replace it with the Central Bank of Tunisia rate.
"""

from dataclasses import dataclass
from typing import Any, Dict

from config.settings import settings


@dataclass(frozen=True)
class Currency:
    code: str
    symbol: str
    rate_from_usd: float

    def convert(self, usd_amount: Any) -> float:
        """Convert a USD amount into the display currency."""
        try:
            return float(usd_amount) * self.rate_from_usd
        except (TypeError, ValueError):
            return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "symbol": self.symbol,
            "rate_from_usd": self.rate_from_usd,
        }


USD = Currency(code="USD", symbol="$", rate_from_usd=1.0)


def get_display_currency() -> Currency:
    """Currency selected in the settings (read at call time, so tests can patch it)."""
    code = str(getattr(settings, "display_currency", "TND")).upper()

    if code == "USD":
        return USD

    rate = float(getattr(settings, "usd_to_tnd_rate", 2.9927))
    if rate <= 0:
        raise ValueError("USD_TO_TND_RATE must be a positive number")

    return Currency(code="TND", symbol="DT", rate_from_usd=rate)
