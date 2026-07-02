import numpy as np
from typing import Dict, Any, Tuple
from scipy import stats
import logging

logger = logging.getLogger(__name__)

class AnomalyProbability:
    """
    Calculate P(anomaly | observed behavior) using statistical methods
    
    Methods:
    - Z-score: deviation from mean in standard deviations
    - Chi-square: distribution comparison
    - Isolation Forest: multivariate outlier
    """
    
    def __init__(self):
        self.z_score_threshold = 2.0  # 95.4% confidence
        self.p_value_threshold = 0.05  # Statistical significance
    
    def calculate_probability(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Tuple[float, Dict]:
        """
        Calculate P(anomaly | event, baseline)
        
        Returns:
            - anomaly_probability: float 0-1
            - details: explanation
        """
        if not baseline:
            return 0.5, {"reason": "No baseline available"}
        
        probabilities = []
        details = {}
        
        # Time-based anomaly
        time_prob = self._time_anomaly_probability(event, baseline)
        probabilities.append(time_prob)
        details["time_anomaly"] = time_prob
        
        # Process-based anomaly
        process_prob = self._process_anomaly_probability(event, baseline)
        probabilities.append(process_prob)
        details["process_anomaly"] = process_prob
        
        # Network-based anomaly
        network_prob = self._network_anomaly_probability(event, baseline)
        probabilities.append(network_prob)
        details["network_anomaly"] = network_prob
        
        # Combine probabilities (weighted)
        combined_prob = (
            0.30 * time_prob +
            0.35 * process_prob +
            0.35 * network_prob
        )
        
        details["combined_probability"] = float(combined_prob)
        details["is_anomaly"] = combined_prob > 0.5
        
        return float(combined_prob), details
    
    def _time_anomaly_probability(self, event: Dict, baseline: Dict) -> float:
        """
        Calculate P(anomaly | time)
        
        Example: User never logged in at 02:37 → high anomaly
        """
        try:
            from datetime import datetime
            event_time = datetime.fromisoformat(event.get("timestamp", "").replace('Z', '+00:00'))
            event_hour = event_time.hour
            
            time_patterns = baseline.get("time_patterns", {})
            active_hours = time_patterns.get("active_hours", list(range(9, 18)))
            
            # If event is at unusual hour
            if event_hour not in active_hours:
                # Check how far from normal
                hour_mean = time_patterns.get("hour_mean", 12)
                hour_std = time_patterns.get("hour_std", 4)
                
                if hour_std == 0:
                    return 0.9 if event_hour not in active_hours else 0.1
                
                z_score = abs((event_hour - hour_mean) / hour_std)
                prob = stats.norm.sf(z_score)  # Survival function = 1 - CDF
                
                return min(prob, 1.0)
            
            return 0.1  # Normal time
        
        except Exception as e:
            logger.error(f"Time anomaly error: {e}")
            return 0.3
    
    def _process_anomaly_probability(self, event: Dict, baseline: Dict) -> float:
        """
        Calculate P(anomaly | process)
        
        Example: User never ran PowerShell → high anomaly
        """
        process_name = event.get("process_name", "").lower()
        
        if not process_name:
            return 0.2
        
        process_patterns = baseline.get("process_patterns", {})
        typical_processes = process_patterns.get("typical_processes", [])
        
        # Check if process is typical
        if any(p.lower() in process_name for p in typical_processes):
            return 0.1  # Normal process
        
        # Unknown process = higher anomaly
        # But check if it's inherently suspicious
        suspicious_keywords = ["powershell", "cmd", "certutil", "psexec", "wmiexec"]
        if any(kw in process_name for kw in suspicious_keywords):
            return 0.7
        
        # Just unknown = moderate anomaly
        return 0.4
    
    def _network_anomaly_probability(self, event: Dict, baseline: Dict) -> float:
        """
        Calculate P(anomaly | network)
        
        Example: User never connects to external IPs → high anomaly
        """
        dest_ip = event.get("destination_ip", "")
        dest_port = event.get("destination_port", 443)
        
        if not dest_ip:
            return 0.1
        
        network_patterns = baseline.get("network_patterns", {})
        typical_ips = network_patterns.get("typical_destinations", [])
        typical_ports = network_patterns.get("typical_ports", [])
        
        # Check if destination is typical
        ip_is_typical = any(tip in dest_ip for tip in typical_ips) if typical_ips else False
        port_is_typical = dest_port in typical_ports if typical_ports else False
        
        if ip_is_typical and port_is_typical:
            return 0.1  # Normal connection
        
        # External destination = higher anomaly
        is_external = not dest_ip.startswith(("192.168", "10.", "172."))
        if is_external:
            return 0.6
        
        # Unusual port = moderate anomaly
        if not port_is_typical:
            return 0.4
        
        return 0.2
    
    def calculate_z_score(self, value: float, mean: float, std: float) -> float:
        """Calculate z-score: how many std devs away from mean"""
        if std == 0:
            return 0.0
        return abs((value - mean) / std)
    
    def z_score_to_probability(self, z_score: float) -> float:
        """Convert z-score to anomaly probability"""
        # P(Z > z_score)
        return float(stats.norm.sf(z_score))

# Singleton
anomaly_probability = AnomalyProbability()
