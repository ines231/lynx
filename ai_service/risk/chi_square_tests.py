import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from scipy import stats

logger = logging.getLogger(__name__)


class ChiSquareTests:
    """
    Chi-square goodness-of-fit tests: observed behaviour vs. baseline.

    H0 : the current window is drawn from the baseline distribution.
    Ha : the current window deviates from the baseline distribution.

    Method
    ------
    * The baseline counts are smoothed (Lidstone, ``smoothing`` pseudo-count per
      category) so that a category never seen in the baseline gets a small but
      non-zero expected probability instead of an arbitrary hand-made mass.
    * The Pearson statistic  X² = Σ (O - E)² / E  is computed over the union of
      baseline and observed categories.
    * p-value:
        - asymptotic chi-square law (df = K - 1) when every expected count is
          >= 5 (the usual validity rule);
        - otherwise an exact Monte-Carlo multinomial test, which stays valid for
          the small windows typical of a SOC (a handful of events).

    Returned score
    --------------
    ``anomaly_prob = 1 - p_value``: the stronger the evidence against H0, the
    closer to 1.  It is an *evidence-of-deviation* score, not a calibrated
    posterior probability of attack.  (The previous version returned the raw
    p-value when the test was not significant, which inverted the meaning.)
    """

    def __init__(
        self,
        p_value_threshold: float = 0.05,
        smoothing: float = 0.5,
        n_simulations: int = 10000,
        seed: Optional[int] = 42,
    ):
        self.p_value_threshold = p_value_threshold
        self.smoothing = smoothing
        self.n_simulations = n_simulations
        self.seed = seed

    # ------------------------------------------------------------------ core
    def _goodness_of_fit(
        self,
        observed: Dict[str, int],
        baseline_counts: Dict[str, float],
    ) -> Dict[str, Any]:
        """Pearson chi-square of ``observed`` against smoothed ``baseline_counts``."""

        categories = list(baseline_counts.keys())
        categories += [c for c in observed if c not in baseline_counts]
        k = len(categories)

        n = int(sum(observed.values()))
        total_baseline = float(sum(baseline_counts.values()))

        alpha = self.smoothing
        probs = np.array(
            [
                (baseline_counts.get(c, 0.0) + alpha) / (total_baseline + alpha * k)
                for c in categories
            ],
            dtype=float,
        )
        probs = probs / probs.sum()

        obs = np.array([observed.get(c, 0) for c in categories], dtype=float)
        exp = probs * n

        chi2_stat = float(np.sum((obs - exp) ** 2 / exp))
        df = k - 1

        if df < 1:
            p_value, method = 1.0, "degenerate"
        elif np.all(exp >= 5):
            p_value, method = float(stats.chi2.sf(chi2_stat, df)), "asymptotic"
        else:
            rng = np.random.default_rng(self.seed)
            sims = rng.multinomial(n, probs, size=self.n_simulations)
            sim_stats = ((sims - exp) ** 2 / exp).sum(axis=1)
            exceed = int(np.sum(sim_stats >= chi2_stat - 1e-9))
            p_value = (exceed + 1) / (self.n_simulations + 1)
            method = "monte_carlo"

        return {
            "chi2_statistic": chi2_stat,
            "p_value": float(p_value),
            "degrees_of_freedom": int(df),
            "method": method,
            "cohens_w": float(np.sqrt(chi2_stat / n)) if n > 0 else 0.0,
            "n_observed": n,
            "new_categories": [c for c in observed if c not in baseline_counts],
            "min_expected_count": float(exp.min()),
        }

    def _finish(
        self,
        test_name: str,
        observed: Dict[str, int],
        baseline_counts: Dict[str, float],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, Dict]:
        result = self._goodness_of_fit(observed, baseline_counts)
        p_value = result["p_value"]
        is_significant = p_value < self.p_value_threshold
        anomaly_prob = min(max(1.0 - p_value, 0.0), 1.0)

        details = {
            "test": test_name,
            **result,
            "p_value_threshold": self.p_value_threshold,
            "is_significant": bool(is_significant),
            "anomaly_probability": float(anomaly_prob),
            "observed_counts": dict(observed),
        }
        if extra:
            details.update(extra)

        return float(anomaly_prob), details

    @staticmethod
    def _count(values: List[Any]) -> Dict[str, int]:
        return {str(k): int(v) for k, v in Counter(values).items()}

    @staticmethod
    def _normalize_counts(raw: Any) -> Dict[str, float]:
        """Accept {category: count} and drop non-positive / invalid entries."""
        if not isinstance(raw, dict):
            return {}
        counts = {}
        for key, value in raw.items():
            try:
                value = float(value)
            except (TypeError, ValueError):
                continue
            if value > 0:
                counts[str(key)] = value
        return counts

    @staticmethod
    def _uniform_from_list(items: Any) -> Dict[str, float]:
        """Fallback for old baselines that only stored a list of typical items."""
        if not items:
            return {}
        return {str(item): 1.0 for item in items}

    # ------------------------------------------------------------- the tests
    def test_process_distribution(
        self, current_events: List[Dict], baseline: Dict
    ) -> Tuple[float, Dict]:
        """Are the processes seen today different from the baseline?"""
        observed_procs = [
            e.get("process_name") for e in current_events if e.get("process_name")
        ]
        if not observed_procs:
            return 0.0, {"test": "no_data"}

        patterns = baseline.get("process_patterns", {})
        baseline_counts = self._normalize_counts(patterns.get("counts"))
        if not baseline_counts:
            baseline_counts = self._uniform_from_list(patterns.get("typical_processes"))
        if not baseline_counts:
            return 0.0, {"test": "no_baseline"}

        return self._finish(
            "process_distribution",
            self._count(observed_procs),
            baseline_counts,
            {"baseline_processes": list(baseline_counts)[:5]},
        )

    def test_port_distribution(
        self, current_events: List[Dict], baseline: Dict
    ) -> Tuple[float, Dict]:
        """Are the destination ports seen today different from the baseline?"""
        observed_ports = [
            e.get("destination_port")
            for e in current_events
            if e.get("destination_port")
        ]
        if not observed_ports:
            return 0.0, {"test": "no_data"}

        patterns = baseline.get("network_patterns", {})
        baseline_counts = self._normalize_counts(patterns.get("port_counts"))
        if not baseline_counts:
            baseline_counts = self._uniform_from_list(patterns.get("typical_ports"))
        if not baseline_counts:
            return 0.0, {"test": "no_baseline"}

        return self._finish(
            "port_distribution",
            self._count([int(p) for p in observed_ports]),
            baseline_counts,
            {"baseline_ports": list(baseline_counts)[:5]},
        )

    def test_event_type_distribution(
        self, current_events: List[Dict], baseline: Dict
    ) -> Tuple[float, Dict]:
        """Compare current event-type frequencies with baseline frequencies."""
        observed_types = [
            e.get("event_type") for e in current_events if e.get("event_type")
        ]
        if not observed_types:
            return 0.0, {"test": "no_data"}

        baseline_counts = self._normalize_counts(baseline.get("event_types", {}))
        if not baseline_counts:
            return 0.0, {"test": "no_baseline"}

        return self._finish(
            "event_type_distribution",
            self._count(observed_types),
            baseline_counts,
            {"baseline_event_types": dict(baseline.get("event_types", {}))},
        )

    def test_severity_distribution(
        self, current_events: List[Dict], baseline: Dict
    ) -> Tuple[float, Dict]:
        """Is the severity mix today different from the baseline?"""
        observed = [e.get("severity") for e in current_events if e.get("severity")]
        if not observed:
            return 0.0, {"test": "no_data"}

        baseline_counts = self._normalize_counts(
            baseline.get("severity_distribution", {})
        )
        if not baseline_counts:
            return 0.0, {"test": "no_baseline"}

        return self._finish(
            "severity_distribution",
            self._count(observed),
            baseline_counts,
        )


# Singleton
chi_square_tests = ChiSquareTests()
