import pandas as pd
import numpy as np
from typing import Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract ML features from security events"""
    
    @staticmethod
    def extract_features(event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from event"""
        features = {}
        
        # Time-based features
        if "timestamp" in event:
            hour = datetime.fromisoformat(event["timestamp"]).hour
            features["hour_of_day"] = hour
            features["is_business_hours"] = 1.0 if 8 <= hour <= 18 else 0.0
        
        # Network features
        if "source_ip" in event:
            features["source_ip_malicious"] = event.get("threat_intel", {}).get("source_ip", {}).get("is_malicious", 0.0)
        
        # Process features
        if "process_name" in event:
            suspicious_processes = ["powershell", "cmd", "certutil", "psexec"]
            features["is_suspicious_process"] = 1.0 if any(p in event["process_name"].lower() for p in suspicious_processes) else 0.0
        
        # File access features
        if "file_path" in event:
            sensitive_paths = ["finance", "hr", "confidential", "secret"]
            features["is_sensitive_file"] = 1.0 if any(p in event["file_path"].lower() for p in sensitive_paths) else 0.0
        
        # Event volume
        features["event_count_1h"] = event.get("event_count_1h", 1.0)
        
        return features
    
    @staticmethod
    def extract_user_baseline_features(events: List[Dict[str, Any]], window_days: int = 90) -> Dict[str, float]:
        """Extract baseline features for a user"""
        if not events:
            return {}
        
        df = pd.DataFrame(events)
        
        baseline = {
            "avg_daily_events": len(events) / window_days,
            "avg_unique_hosts": df["destination_ip"].nunique() / window_days if "destination_ip" in df else 0,
            "avg_files_accessed": df["file_path"].nunique() / window_days if "file_path" in df else 0,
            "avg_logins_per_day": len(df[df["event_type"] == "login"]) / window_days if "event_type" in df else 0,
            "typical_hours_active": df["hour_of_day"].mode()[0] if "hour_of_day" in df and len(df) > 0 else 9,
        }
        
        return baseline
