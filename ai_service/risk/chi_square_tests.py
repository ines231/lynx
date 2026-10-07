import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, List, Tuple, Any
import logging

logger = logging.getLogger(__name__)

class ChiSquareTests:
    """
    Statistical hypothesis testing using Chi-Square
    
    Compares observed vs expected distributions:
    - Process distribution
    - Port distribution
    - Event type distribution
    - Severity distribution
    """
    
    def __init__(self, p_value_threshold: float = 0.05):
        self.p_value_threshold = p_value_threshold
    
    def test_process_distribution(self, current_events: List[Dict], baseline: Dict) -> Tuple[float, Dict]:
        """
        Chi-square test: Are processes today different from baseline?
        
        H0: Process distribution today == baseline distribution
        Ha: Process distribution today != baseline distribution
        """
        # Get observed processes
        observed_procs = [e.get("process_name") for e in current_events if e.get("process_name")]
        
        if not observed_procs:
            return 0.0, {"test": "no_data"}
        
        baseline_procs = baseline.get("process_patterns", {}).get("typical_processes", [])
        
        if not baseline_procs:
            return 0.0, {"test": "no_baseline"}
        
        # Count occurrences
        observed_counts = pd.Series(observed_procs).value_counts()
        
        # Expected is uniform across baseline processes
        expected_counts = np.ones(len(baseline_procs)) * (len(observed_procs) / len(baseline_procs))
        
        # Chi-square test (only compare observed vs baseline)
        common_procs = [p for p in observed_counts.index if p in baseline_procs]
        
        if not common_procs:
            # All observed processes are unusual
            chi2_stat = len(observed_procs)  # High chi-square value
            p_value = 0.001
        else:
            observed_vals = [observed_counts[p] for p in common_procs]
            expected_vals = [len(observed_procs) / len(common_procs)] * len(common_procs)
            
            chi2_stat, p_value = stats.chisquare(observed_vals, expected_vals)
        
        is_significant = p_value < self.p_value_threshold
        anomaly_prob = min(1.0 - p_value, 1.0) if is_significant else p_value
        
        return float(anomaly_prob), {
            "test": "process_distribution",
            "chi2_statistic": float(chi2_stat),
            "p_value": float(p_value),
            "is_significant": bool(is_significant),
            "observed_processes": list(observed_counts.head(5).index),
            "baseline_processes": baseline_procs[:5]
        }
    
    def test_port_distribution(self, current_events: List[Dict], baseline: Dict) -> Tuple[float, Dict]:
        """
        Chi-square test: Are destination ports today different from baseline?
        """
        observed_ports = [e.get("destination_port") for e in current_events if e.get("destination_port")]
        
        if not observed_ports:
            return 0.0, {"test": "no_data"}
        
        baseline_ports = baseline.get("network_patterns", {}).get("typical_ports", [])
        
        if not baseline_ports:
            return 0.0, {"test": "no_baseline"}
        
        observed_counts = pd.Series(observed_ports).value_counts()
        common_ports = [p for p in observed_counts.index if p in baseline_ports]
        
        if not common_ports:
            chi2_stat = len(observed_ports)
            p_value = 0.001
        elif len(common_ports) < 2:
            chi2_stat = 0.0
            p_value = 1.0
        else:
            observed_vals = [observed_counts[p] for p in common_ports]
            expected_vals = [len(observed_ports) / len(common_ports)] * len(common_ports)
            chi2_stat, p_value = stats.chisquare(observed_vals, expected_vals)
        
        is_significant = p_value < self.p_value_threshold
        anomaly_prob = min(1.0 - p_value, 1.0) if is_significant else p_value
        
        return float(anomaly_prob), {
            "test": "port_distribution",
            "chi2_statistic": float(chi2_stat),
            "p_value": float(p_value),
            "is_significant": bool(is_significant),
            "observed_ports": sorted(list(set([int(p) for p in observed_counts.head(5).index]))),
            "baseline_ports": sorted(baseline_ports[:5])
        }
    
    def test_event_type_distribution(self, current_events: List[Dict], baseline: Dict) -> Tuple[float, Dict]:
        """Compare current event-type frequencies with baseline frequencies."""
        observed_types = [
            e.get("event_type")
            for e in current_events
            if e.get("event_type")
        ]

        if not observed_types:
            return 0.0, {"test": "no_data"}

        baseline_types = baseline.get("event_types", {})
        if not baseline_types:
            return 0.0, {"test": "no_baseline"}

        observed_counts = pd.Series(observed_types).value_counts()
        baseline_counts = {
            str(k): float(v)
            for k, v in baseline_types.items()
            if v is not None and float(v) > 0
        }
        total_baseline = sum(baseline_counts.values())
        if total_baseline <= 0:
            return 0.0, {"test": "invalid_baseline"}

        categories = list(baseline_counts.keys())
        for event_type in observed_counts.index:
            event_type = str(event_type)
            if event_type not in categories:
                categories.append(event_type)

        expected_probs = [
            baseline_counts.get(category, 0.0) / total_baseline
            for category in categories
        ]

        unseen = [
            i for i, category in enumerate(categories)
            if category not in baseline_counts
        ]
        if unseen:
            seen_mass = sum(expected_probs)
            remaining_mass = max(1.0 - seen_mass, 0.0)
            if remaining_mass == 0:
                remaining_mass = 0.01 * len(unseen)
                expected_probs = [p * (1.0 - remaining_mass) for p in expected_probs]
            share = remaining_mass / len(unseen)
            for i in unseen:
                expected_probs[i] = share

        total_observed = len(observed_types)
        observed_vals = [float(observed_counts.get(category, 0)) for category in categories]
        expected_vals = [max(p * total_observed, 1e-9) for p in expected_probs]

        chi2_stat, p_value = stats.chisquare(observed_vals, expected_vals)
        is_significant = p_value < self.p_value_threshold
        anomaly_prob = min(1.0 - p_value, 1.0) if is_significant else p_value

        return float(anomaly_prob), {
            "test": "event_type_distribution",
            "chi2_statistic": float(chi2_stat),
            "p_value": float(p_value),
            "is_significant": bool(is_significant),
            "observed_event_types": dict(observed_counts.head(10)),
            "baseline_event_types": baseline_types
        }
# Singleton
chi_square_tests = ChiSquareTests()
