import numpy as np
from typing import Dict, Any, Tuple
from scipy import stats
import logging

from ai_service.risk.common import is_private_ip

logger = logging.getLogger(__name__)


class AnomalyProbability:
    """
    Calculate P(anomaly | observed behavior) using statistical methods.

    Methods:
    - Z-score: deviation from mean in standard deviations
    - Chi-square: distribution comparison
    - Isolation Forest: multivariate outlier
    """

    def __init__(self):
        self.z_score_threshold = 2.0
        self.p_value_threshold = 0.05

    @staticmethod
    def _get_value(event: Any, key: str, default=None):
        """
        Read a field from either a dictionary or a Pydantic/model object.
        """
        if isinstance(event, dict):
            return event.get(key, default)

        return getattr(event, key, default)

    def calculate_probability(
        self,
        event: Any,
        baseline: Dict[str, Any]
    ) -> Tuple[float, Dict]:
        """
        Calculate P(anomaly | event, baseline).

        Returns:
            - anomaly_probability: float between 0 and 1
            - details: explanation of the calculation
        """

        if not baseline:
            return 0.5, {"reason": "No baseline available"}

        probabilities = []
        details = {}

        # Time-based anomaly
        time_prob = self._time_anomaly_probability(
            event,
            baseline
        )
        probabilities.append(time_prob)
        details["time_anomaly"] = time_prob

        # Process-based anomaly
        process_prob = self._process_anomaly_probability(
            event,
            baseline
        )
        probabilities.append(process_prob)
        details["process_anomaly"] = process_prob

        # Network-based anomaly
        network_prob = self._network_anomaly_probability(
            event,
            baseline
        )
        probabilities.append(network_prob)
        details["network_anomaly"] = network_prob

        # Event-type rarity: how unusual is this kind of event for this
        # baseline? Before this component the score ignored the event type
        # entirely, so a privilege escalation from a "known" process and no
        # network fields scored 10%.
        type_prob = self._event_type_anomaly_probability(
            event,
            baseline
        )

        if type_prob is not None:
            probabilities.append(type_prob)
            details["event_type_anomaly"] = type_prob

            combined_prob = (
                0.20 * time_prob +
                0.25 * process_prob +
                0.25 * network_prob +
                0.30 * type_prob
            )
        else:
            # Old baselines without event_types keep the previous weights.
            combined_prob = (
                0.30 * time_prob +
                0.35 * process_prob +
                0.35 * network_prob
            )

        details["combined_probability"] = float(combined_prob)
        details["is_anomaly"] = combined_prob > 0.5

        return float(combined_prob), details

    def _time_anomaly_probability(
        self,
        event: Any,
        baseline: Dict[str, Any]
    ) -> float:
        """Calculate P(anomaly | time)."""

        try:
            from datetime import datetime

            timestamp = self._get_value(
                event,
                "timestamp",
                ""
            )

            if not timestamp:
                return 0.3

            if hasattr(timestamp, "hour"):
                event_time = timestamp
            else:
                event_time = datetime.fromisoformat(
                    str(timestamp).replace("Z", "+00:00")
                )

            event_hour = event_time.hour

            time_patterns = baseline.get(
                "time_patterns",
                {}
            )

            active_hours = time_patterns.get(
                "active_hours",
                list(range(9, 18))
            )

            if event_hour not in active_hours:
                hour_mean = time_patterns.get(
                    "hour_mean",
                    12
                )

                hour_std = time_patterns.get(
                    "hour_std",
                    4
                )

                if hour_std == 0:
                    return (
                        0.9
                        if event_hour not in active_hours
                        else 0.1
                    )

                z_score = abs(
                    (event_hour - hour_mean)
                    / hour_std
                )

                # Two-sided deviation score in [0, 1]:
                #   P(|Z| <= z) = 1 - 2 * sf(z)
                # The previous 1 - sf(z) was the one-sided CDF, which is
                # already 0.5 for z = 0, so even a typical hour looked
                # "50% anomalous". The floor keeps an off-peak hour at least
                # as suspicious as an hour listed in the baseline (0.1).
                prob = 1.0 - 2.0 * stats.norm.sf(z_score)

                return min(max(float(prob), 0.1), 0.95)

            return 0.1

        except Exception as e:
            logger.error(
                f"Time anomaly error: {e}"
            )
            return 0.3

    def _event_type_anomaly_probability(
        self,
        event: Any,
        baseline: Dict[str, Any]
    ):
        """
        Rarity of the event type in the baseline, in [0.1, 0.95].

        Uses Lidstone-smoothed frequencies so an unseen type gets a small
        non-zero probability, then scores the type relative to the most
        common one: 1 - p(type) / p(most common type).
        Returns None when the baseline has no event-type counts.
        """

        counts = baseline.get("event_types") or {}

        event_type = str(
            self._get_value(event, "event_type", "") or ""
        )

        if not counts or not event_type:
            return None

        try:
            counts = {
                str(name): float(count)
                for name, count in counts.items()
                if float(count) > 0
            }
        except (TypeError, ValueError):
            return None

        if not counts:
            return None

        alpha = 0.5
        categories = len(counts) + (
            0 if event_type in counts else 1
        )
        denominator = sum(counts.values()) + alpha * categories

        p_event = (counts.get(event_type, 0.0) + alpha) / denominator
        p_max = (max(counts.values()) + alpha) / denominator

        score = 1.0 - p_event / p_max

        return min(max(float(score), 0.1), 0.95)

    def _process_anomaly_probability(
        self,
        event: Any,
        baseline: Dict[str, Any]
    ) -> float:
        """Calculate P(anomaly | process)."""

        process_name = self._get_value(
            event,
            "process_name",
            ""
        )

        process_name = str(
            process_name or ""
        ).lower()

        if not process_name:
            return 0.2

        process_patterns = baseline.get(
            "process_patterns",
            {}
        )

        typical_processes = process_patterns.get(
            "typical_processes",
            []
        )

        # Ignore empty names: "" in any string is always True.
        typical_processes = [
            str(process).lower()
            for process in typical_processes
            if process
        ]

        if any(
            process in process_name
            for process in typical_processes
        ):
            return 0.1

        suspicious_keywords = [
            "powershell",
            "cmd",
            "certutil",
            "psexec",
            "wmiexec"
        ]

        if any(
            keyword in process_name
            for keyword in suspicious_keywords
        ):
            return 0.7

        return 0.4

    def _network_anomaly_probability(
        self,
        event: Any,
        baseline: Dict[str, Any]
    ) -> float:
        """Calculate P(anomaly | network)."""

        dest_ip = self._get_value(
            event,
            "destination_ip",
            ""
        )

        # No default port: a missing port must not be treated as the
        # typical 443.
        dest_port = self._get_value(
            event,
            "destination_port",
            None
        )

        dest_ip = str(dest_ip or "")

        if not dest_ip:
            return 0.1

        network_patterns = baseline.get(
            "network_patterns",
            {}
        )

        typical_ips = network_patterns.get(
            "typical_destinations",
            []
        )

        typical_ports = network_patterns.get(
            "typical_ports",
            []
        )

        # Exact match: the old substring test made "192.168.1.10" match
        # "192.168.1.100".
        ip_is_typical = dest_ip in {
            str(tip) for tip in typical_ips
        }

        try:
            port_is_typical = (
                dest_port is not None
                and int(dest_port) in {
                    int(port) for port in typical_ports
                }
            )
        except (TypeError, ValueError):
            port_is_typical = False

        if ip_is_typical and port_is_typical:
            return 0.1

        # Real RFC1918 check (172.x is private only for 172.16.0.0/12).
        is_private = is_private_ip(dest_ip)

        if not is_private:
            return 0.6

        if not port_is_typical:
            return 0.4

        return 0.2

    def calculate_z_score(
        self,
        value: float,
        mean: float,
        std: float
    ) -> float:
        """Calculate absolute z-score."""

        if std == 0:
            return 0.0

        return abs(
            (value - mean) / std
        )

    def z_score_to_probability(
        self,
        z_score: float
    ) -> float:
        """Convert z-score to anomaly probability."""

        return float(
            stats.norm.sf(z_score)
        )


# Singleton
anomaly_probability = AnomalyProbability()