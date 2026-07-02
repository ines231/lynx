import numpy as np
from typing import Dict, List, Any, Tuple
import logging

logger = logging.getLogger(__name__)

class MonteCarloFAIR:
    """
    FAIR (Factor Analysis of Information Risk) using Monte Carlo simulation
    
    Calculates:
    - Loss Event Frequency (LEF)
    - Probable Loss Magnitude (PLM)
    - Annual Loss Expectancy (ALE)
    - Risk distribution (value at risk, expected shortfall)
    """
    
    def __init__(self, simulations: int = 10000):
        self.simulations = simulations
    
    def calculate_risk(self, event: Dict[str, Any], anomaly_prob: float) -> Dict[str, Any]:
        """
        Calculate FAIR risk from an event
        
        FAIR formula:
        Risk = Threat Event Frequency (TEF) × Vulnerability (V) × Loss Magnitude (LM)
        
        More detailed:
        Risk = LEF × PLM
        where:
          LEF = Loss Event Frequency = TEF × V
          PLM = Probable Loss Magnitude
        """
        
        # Step 1: Estimate Threat Event Frequency
        tef = self._estimate_threat_event_frequency(event, anomaly_prob)
        
        # Step 2: Estimate Vulnerability (probability threat succeeds)
        vulnerability = self._estimate_vulnerability(event, anomaly_prob)
        
        # Step 3: Loss Event Frequency = TEF × Vulnerability
        lef = tef * vulnerability
        
        # Step 4: Estimate Probable Loss Magnitude
        plm = self._estimate_loss_magnitude(event)
        
        # Step 5: Monte Carlo simulation
        loss_dist = self._monte_carlo_loss_distribution(lef, plm)
        
        # Step 6: Compute risk metrics
        annual_loss_expectancy = lef * plm
        var_95 = np.percentile(loss_dist, 95)
        var_99 = np.percentile(loss_dist, 99)
        expected_shortfall_95 = np.mean(loss_dist[loss_dist >= var_95])
        
        return {
            "threat_event_frequency": float(tef),
            "vulnerability": float(vulnerability),
            "loss_event_frequency": float(lef),
            "probable_loss_magnitude": float(plm),
            "annual_loss_expectancy": float(annual_loss_expectancy),
            "value_at_risk_95": float(var_95),
            "value_at_risk_99": float(var_99),
            "expected_shortfall_95": float(expected_shortfall_95),
            "loss_distribution": loss_dist.tolist()[:100],  # Sample for output
            "recommendation": self._recommend_treatment(annual_loss_expectancy, var_95)
        }
    
    def _estimate_threat_event_frequency(self, event: Dict, anomaly_prob: float) -> float:
        """
        Estimate how often this threat occurs
        
        TEF ranges from 0-1 (per year)
        - 0.01 = happens 1 time per 100 years
        - 0.1 = happens 1 time per 10 years
        - 1.0 = happens every year
        - 10.0 = happens 10 times per year
        """
        base_tef = 0.01  # Default: rare
        
        # Adjust based on event type
        event_type = event.get("event_type", "").lower()
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
        
        # Adjust by anomaly probability
        tef = base_tef * (1 + anomaly_prob * 9)  # 0.5 anomaly → 5x tef
        
        return min(tef, 365.0)  # Cap at ~1 per day
    
    def _estimate_vulnerability(self, event: Dict, anomaly_prob: float) -> float:
        """
        Estimate probability that threat succeeds given TEF
        
        V ranges from 0-1
        - 0.1 = 10% chance attacker succeeds
        - 0.5 = 50% chance
        - 0.9 = 90% chance
        """
        base_vulnerability = 0.2
        
        # Check if threat intel indicates compromise
        threat_intel = event.get("threat_intel", {})
        if threat_intel.get("source_ip", {}).get("is_malicious", False):
            base_vulnerability += 0.3
        
        if threat_intel.get("destination_ip", {}).get("is_malicious", False):
            base_vulnerability += 0.2
        
        # Adjust by anomaly
        vulnerability = base_vulnerability + (anomaly_prob * 0.4)
        
        return min(vulnerability, 0.99)
    
    def _estimate_loss_magnitude(self, event: Dict) -> float:
        """
        Estimate financial loss if threat succeeds
        
        Considers:
        - What data is at risk
        - How many systems affected
        - Business impact
        """
        base_loss = 5000  # USD
        
        event_type = event.get("event_type", "").lower()
        
        # Loss multipliers by event type
        multipliers = {
            "exfiltration": {"base": 50000, "reason": "data_loss"},
            "privilege_escalation": {"base": 30000, "reason": "system_compromise"},
            "lateral_movement": {"base": 25000, "reason": "network_spread"},
            "persistence": {"base": 20000, "reason": "ongoing_access"},
            "exploitation": {"base": 15000, "reason": "vulnerability_use"},
            "reconnaissance": {"base": 5000, "reason": "reconnaissance_only"},
        }
        
        for key, data in multipliers.items():
            if key in event_type:
                base_loss = data["base"]
                break
        
        # Check if sensitive files involved
        file_path = event.get("file_path", "").lower()
        if any(s in file_path for s in ["finance", "confidential", "hr", "salary"]):
            base_loss *= 3
        
        return float(base_loss)
    
    def _monte_carlo_loss_distribution(self, lef: float, plm: float) -> np.ndarray:
        """
        Simulate loss distribution with Monte Carlo
        
        Generates random loss scenarios for 1 year
        """
        # Number of loss events follows Poisson distribution
        num_events = np.random.poisson(lef, self.simulations)
        
        # Each event's magnitude varies (lognormal distribution)
        # This captures uncertainty in PLM
        sigma = 0.3  # 30% coefficient of variation
        
        total_losses = []
        for n_events in num_events:
            if n_events == 0:
                total_losses.append(0)
            else:
                # Each event: lognormal around PLM
                event_losses = np.random.lognormal(
                    mean=np.log(plm) - sigma**2 / 2,
                    sigma=sigma,
                    size=n_events
                )
                total_losses.append(np.sum(event_losses))
        
        return np.array(total_losses)
    
    @staticmethod
    def _recommend_treatment(ale: float, var_95: float) -> str:
        """
        Recommend treatment based on risk level
        
        FAIR treatment:
        - Remediate: High risk, reduce TEF or V
        - Accept: Low risk, tolerable
        - Mitigate: Medium risk, reduce LM with controls
        - Transfer: Buy insurance, share risk
        """
        if ale > 50000 or var_95 > 150000:
            return "REMEDIATE_URGENT: Risk is critical, implement immediate controls"
        elif ale > 20000 or var_95 > 75000:
            return "REMEDIATE: Risk is high, prioritize patches and hardening"
        elif ale > 10000:
            return "MITIGATE: Risk is moderate, implement compensating controls"
        elif ale > 5000:
            return "MITIGATE_OR_ACCEPT: Consider insurance or compensating controls"
        else:
            return "ACCEPT: Risk is low and tolerable, monitor"

# Singleton
monte_carlo_fair = MonteCarloFAIR()
