import numpy as np
from typing import Dict, Any, Tuple
from scipy import stats
import logging

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

        # Weighted combination
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

                # Convert deviation into an intuitive
                # anomaly score rather than returning
                # the small statistical tail probability.
                prob = 1 - stats.norm.sf(z_score)

                return min(max(float(prob), 0.0), 1.0)

            return 0.1

        except Exception as e:
            logger.error(
                f"Time anomaly error: {e}"
            )
            return 0.3

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

        typical_processes = [
            str(process).lower()
            for process in typical_processes
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

        dest_port = self._get_value(
            event,
            "destination_port",
            443
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

        ip_is_typical = (
            any(
                str(tip) in dest_ip
                for tip in typical_ips
            )
            if typical_ips
            else False
        )

        port_is_typical = (
            dest_port in typical_ports
            if typical_ports
            else False
        )

        if ip_is_typical and port_is_typical:
            return 0.1

        # RFC1918 private network ranges
        is_private = (
            dest_ip.startswith("192.168.")
            or dest_ip.startswith("10.")
            or dest_ip.startswith("172.")
        )

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