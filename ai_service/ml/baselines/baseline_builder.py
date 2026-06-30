import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from ai_service.ml.features.extractor import FeatureExtractor
import logging

logger = logging.getLogger(__name__)

class BaselineBuilder:
    """Build behavioral baselines from historical events"""
    
    def __init__(self, window_days: int = 90):
        self.window_days = window_days
        self.baselines = {}  # user -> baseline stats
        self.feature_names = FeatureExtractor.get_feature_names()
    
    def build_user_baseline(self, user: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build baseline for a specific user
        
        Returns dict with:
        - mean, std, min, max for each feature
        - event_count, unique_hosts, etc.
        """
        if not events:
            logger.warning(f"No events for user {user}")
            return {}
        
        # Extract features
        X, feature_names, _ = FeatureExtractor.extract_batch_features(events)
        
        baseline = {
            "user": user,
            "event_count": len(events),
            "feature_means": np.mean(X, axis=0).tolist(),
            "feature_stds": np.std(X, axis=0).tolist(),
            "feature_mins": np.min(X, axis=0).tolist(),
            "feature_maxs": np.max(X, axis=0).tolist(),
            "feature_names": feature_names,
            "unique_hosts": len(set(e.get("hostname") for e in events)),
            "unique_ips": len(set(e.get("destination_ip") for e in events)),
            "common_processes": self._get_common_values(events, "process_name", top_n=5),
            "common_ports": self._get_common_values(events, "destination_port", top_n=5),
            "typical_hours": self._get_typical_hours(events),
        }
        
        self.baselines[user] = baseline
        logger.info(f"Built baseline for user {user} with {len(events)} events")
        
        return baseline
    
    def build_system_baseline(self, hostname: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build baseline for a specific system/hostname"""
        if not events:
            logger.warning(f"No events for system {hostname}")
            return {}
        
        X, feature_names, _ = FeatureExtractor.extract_batch_features(events)
        
        baseline = {
            "hostname": hostname,
            "event_count": len(events),
            "feature_means": np.mean(X, axis=0).tolist(),
            "feature_stds": np.std(X, axis=0).tolist(),
            "feature_names": feature_names,
            "unique_users": len(set(e.get("user") for e in events)),
            "unique_processes": len(set(e.get("process_name") for e in events)),
            "common_processes": self._get_common_values(events, "process_name", top_n=5),
            "event_types": self._get_common_values(events, "event_type", top_n=5),
        }
        
        self.baselines[hostname] = baseline
        logger.info(f"Built baseline for system {hostname} with {len(events)} events")
        
        return baseline
    
    def get_user_baseline(self, user: str) -> Dict[str, Any]:
        """Get baseline for a user"""
        return self.baselines.get(user, {})
    
    def calculate_deviation(self, user: str, feature_vector: np.ndarray) -> Tuple[float, Dict]:
        """
        Calculate deviation from baseline
        
        Returns:
        - deviation_score: standard deviations from mean
        - details: dict with per-feature deviations
        """
        baseline = self.baselines.get(user)
        if not baseline:
            return 0.0, {}
        
        means = np.array(baseline["feature_means"])
        stds = np.array(baseline["feature_stds"])
        
        # Avoid division by zero
        stds = np.where(stds == 0, 1.0, stds)
        
        # Calculate z-score for each feature
        z_scores = np.abs((feature_vector - means) / stds)
        
        # Maximum deviation (worst feature)
        max_deviation = np.max(z_scores)
        
        # Average deviation across features
        avg_deviation = np.mean(z_scores)
        
        details = {
            "max_deviation_score": float(max_deviation),
            "avg_deviation_score": float(avg_deviation),
            "deviating_features": [
                {
                    "feature": self.feature_names[i],
                    "z_score": float(z_scores[i]),
                    "actual": float(feature_vector[i]),
                    "expected": float(means[i])
                }
                for i in np.argsort(z_scores)[-3:]  # Top 3 deviating features
            ]
        }
        
        return max_deviation, details
    
    @staticmethod
    def _get_common_values(events: List[Dict], key: str, top_n: int = 5) -> List[str]:
        """Get most common values for a key"""
        values = [e.get(key) for e in events if e.get(key)]
        if not values:
            return []
        
        value_counts = pd.Series(values).value_counts()
        return value_counts.head(top_n).index.tolist()
    
    @staticmethod
    def _get_typical_hours(events: List[Dict]) -> List[int]:
        """Get hours when user is typically active"""
        hours = []
        for event in events:
            if "timestamp" in event:
                try:
                    from datetime import datetime
                    ts = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                    hours.append(ts.hour)
                except:
                    pass
        
        if not hours:
            return list(range(9, 18))  # Default: 9am-5pm
        
        # Return hours with highest activity
        hour_counts = pd.Series(hours).value_counts()
        return sorted(hour_counts.head(5).index.tolist())

# Singleton
baseline_builder = BaselineBuilder()
