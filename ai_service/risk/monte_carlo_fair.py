import numpy as np
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class MonteCarloFAIR:
    """
    FAIR (Factor Analysis of Information Risk) using Monte Carlo simulation.

    Calculates:
    - Threat Event Frequency (TEF)
    - Vulnerability
    - Loss Event Frequency (LEF)
    - Probable Loss Magnitude (PLM)
    - Annual Loss Expectancy (ALE)
    - Loss distribution
    - Value at Risk (VaR)
    - Expected Shortfall
    """

    def __init__(self, simulations: int = 10000):
        self.simulations = simulations

    @staticmethod
    def _get_value(event: Any, key: str, default=None):
        """
        Read a field from either a dictionary or a Pydantic/model object.
        """
        if isinstance(event, dict):
            return event.get(key, default)

        return getattr(event, key, default)

    def calculate_risk(
        self,
        event: Any,
        anomaly_prob: float
    ) -> Dict[str, Any]:
        """
        Calculate FAIR risk from an event.

        FAIR:
            LEF = TEF × Vulnerability
            ALE = LEF × PLM
        """

        # ---------------------------------------------------------
        # 1. Threat Event Frequency
        # ---------------------------------------------------------

        tef = self._estimate_threat_event_frequency(
            event,
            anomaly_prob
        )

        # ---------------------------------------------------------
        # 2. Vulnerability
        # ---------------------------------------------------------

        vulnerability = self._estimate_vulnerability(
            event,
            anomaly_prob
        )

        # ---------------------------------------------------------
        # 3. Loss Event Frequency
        # ---------------------------------------------------------

        lef = tef * vulnerability

        # ---------------------------------------------------------
        # 4. Probable Loss Magnitude
        # ---------------------------------------------------------

        plm = self._estimate_loss_magnitude(event)

        # ---------------------------------------------------------
        # 5. Monte Carlo simulation
        # ---------------------------------------------------------

        loss_dist = self._monte_carlo_loss_distribution(
            lef,
            plm
        )

        # ---------------------------------------------------------
        # 6. FAIR metrics
        # ---------------------------------------------------------

        annual_loss_expectancy = lef * plm

        # Use only positive losses for percentile calculations
        positive_losses = loss_dist[
            loss_dist > 0
        ]

        if len(positive_losses) > 0:
            var_95 = float(
                np.percentile(
                    positive_losses,
                    95
                )
            )

            var_99 = float(
                np.percentile(
                    positive_losses,
                    99
                )
            )

            tail_losses = positive_losses[
                positive_losses >= var_95
            ]

            expected_shortfall_95 = float(
                np.mean(tail_losses)
            ) if len(tail_losses) > 0 else 0.0

        else:
            var_95 = 0.0
            var_99 = 0.0
            expected_shortfall_95 = 0.0

        return {
            "threat_event_frequency": float(tef),
            "vulnerability": float(vulnerability),
            "loss_event_frequency": float(lef),
            "probable_loss_magnitude": float(plm),
            "annual_loss_expectancy": float(
                annual_loss_expectancy
            ),
            "value_at_risk_95": var_95,
            "value_at_risk_99": var_99,
            "expected_shortfall_95": expected_shortfall_95,

            # Keep only a sample for API responses
            "loss_distribution": loss_dist.tolist()[:100],

            "recommendation": self._recommend_treatment(
                annual_loss_expectancy,
                var_95
            ),
        }

    def _estimate_threat_event_frequency(
        self,
        event: Any,
        anomaly_prob: float
    ) -> float:
        """
        Estimate threat event frequency.

        TEF = estimated number of threat events per year.
        """

        base_tef = 0.01

        event_type = self._get_value(
            event,
            "event_type",
            ""
        )

        event_type = str(
            event_type or ""
        ).lower()

        event_multipliers = {
            "privilege_escalation": 5.0,
            "lateral_movement": 4.0,
            "exfiltration": 3.0,
            "persistence": 2.0,
            "exploitation": 2.5,
            "reconnaissance": 1.5,
        }

        for key, multiplier in event_multipliers.items():
            if key in event_type:
                base_tef *= multiplier
                break

        # Anomaly increases estimated threat frequency
        tef = base_tef * (
            1 + anomaly_prob * 9
        )

        return min(
            tef,
            365.0
        )

    def _estimate_vulnerability(
        self,
        event: Any,
        anomaly_prob: float
    ) -> float:
        """
        Estimate probability that the threat succeeds.
        """

        base_vulnerability = 0.2

        threat_intel = self._get_value(
            event,
            "threat_intel",
            {}
        )

        if threat_intel is None:
            threat_intel = {}

        if hasattr(threat_intel, "model_dump"):
            threat_intel = threat_intel.model_dump()

        if not isinstance(threat_intel, dict):
            threat_intel = {}

        source_ip_info = threat_intel.get(
            "source_ip",
            {}
        )

        destination_ip_info = threat_intel.get(
            "destination_ip",
            {}
        )

        if hasattr(source_ip_info, "model_dump"):
            source_ip_info = source_ip_info.model_dump()

        if hasattr(destination_ip_info, "model_dump"):
            destination_ip_info = (
                destination_ip_info.model_dump()
            )

        if isinstance(source_ip_info, dict):
            if source_ip_info.get(
                "is_malicious",
                False
            ):
                base_vulnerability += 0.3

        if isinstance(destination_ip_info, dict):
            if destination_ip_info.get(
                "is_malicious",
                False
            ):
                base_vulnerability += 0.2

        vulnerability = (
            base_vulnerability
            + anomaly_prob * 0.4
        )

        return min(
            vulnerability,
            0.99
        )

    def _estimate_loss_magnitude(
        self,
        event: Any
    ) -> float:
        """
        Estimate financial loss if the threat succeeds.
        """

        base_loss = 5000.0

        event_type = self._get_value(
            event,
            "event_type",
            ""
        )

        event_type = str(
            event_type or ""
        ).lower()

        multipliers = {
            "exfiltration": 50000,
            "privilege_escalation": 30000,
            "lateral_movement": 25000,
            "persistence": 20000,
            "exploitation": 15000,
            "reconnaissance": 5000,
        }

        for key, loss_value in multipliers.items():
            if key in event_type:
                base_loss = float(
                    loss_value
                )
                break

        file_path = self._get_value(
            event,
            "file_path",
            ""
        )

        file_path = str(
            file_path or ""
        ).lower()

        sensitive_keywords = [
            "finance",
            "confidential",
            "hr",
            "salary",
        ]

        if any(
            keyword in file_path
            for keyword in sensitive_keywords
        ):
            base_loss *= 3

        return float(base_loss)

    def _monte_carlo_loss_distribution(
        self,
        lef: float,
        plm: float
    ) -> np.ndarray:
        """
        Simulate annual loss distribution.

        A Poisson model determines how many loss events
        occur during a year.

        A lognormal distribution models the magnitude
        of each loss event.
        """

        num_events = np.random.poisson(
            lef,
            self.simulations
        )

        sigma = 0.3

        total_losses = np.zeros(
            self.simulations,
            dtype=float
        )

        active = num_events > 0

        # Number of simulations where at least one
        # loss event occurs.
        active_count = np.sum(active)

        if active_count == 0:
            return total_losses

        # Generate losses for each simulation.
        for index in np.where(active)[0]:

            n_events = num_events[index]

            event_losses = np.random.lognormal(
                mean=np.log(plm) - sigma ** 2 / 2,
                sigma=sigma,
                size=n_events
            )

            total_losses[index] = float(
                np.sum(event_losses)
            )

        return total_losses

    @staticmethod
    def _recommend_treatment(
        ale: float,
        var_95: float
    ) -> str:
        """
        Recommend treatment based on risk metrics.
        """

        if ale > 50000 or var_95 > 150000:
            return (
                "REMEDIATE_URGENT: "
                "Risk is critical, implement immediate controls"
            )

        if ale > 20000 or var_95 > 75000:
            return (
                "REMEDIATE: "
                "Risk is high, prioritize patches and hardening"
            )

        if ale > 10000:
            return (
                "MITIGATE: "
                "Risk is moderate, implement compensating controls"
            )

        if ale > 5000:
            return (
                "MITIGATE_OR_ACCEPT: "
                "Consider insurance or compensating controls"
            )

        return (
            "ACCEPT: "
            "Risk is low and tolerable, monitor"
        )


# Singleton
monte_carlo_fair = MonteCarloFAIR()