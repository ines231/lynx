from ai_service.ml.anomaly.isolation_forest import detector
from ai_service.ml.baselines.baseline_builder import baseline_builder
from ai_service.ml.features.extractor import FeatureExtractor
from ai_service.connectors.models.event import SecurityEvent
from typing import Dict, List, Any
import numpy as np
import logging

logger = logging.getLogger(__name__)

class AnomalyService:
    """Service for anomaly detection and analysis"""
    
    def __init__(self):
        self.detector = detector
        self.baseline_builder = baseline_builder
        self.feature_extractor = FeatureExtractor()
    
    def train_detector(self, events: List[Dict]) -> Dict:
        """Train the anomaly detector on historical events"""
        logger.info(f"Training detector on {len(events)} events")
        
        # Train Isolation Forest
        result = self.detector.train(events)
        
        if result["status"] == "success":
            # Save model
            self.detector.save_model()
            logger.info("Detector trained and saved")
        
        return result
    
    def build_user_baselines(self, events_by_user: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        """Build baselines for multiple users"""
        results = {}
        
        for user, events in events_by_user.items():
            baseline = self.baseline_builder.build_user_baseline(user, events)
            results[user] = baseline
        
        logger.info(f"Built baselines for {len(results)} users")
        return results
    
    def detect_anomaly(self, event: Dict) -> Dict:
        """
        Detect if event is anomalous
        Combines:
        1. Isolation Forest outlier detection
        2. Baseline deviation analysis
        """
        # Get Isolation Forest detection
        is_outlier, outlier_score, outlier_details = self.detector.detect_anomaly(event)
        
        # Get baseline deviation (if user baseline exists)
        baseline_deviation = 0.0
        baseline_details = {}
        
        user = event.get("user")
        if user:
            features = FeatureExtractor.extract_event_features(event)
            feature_vector = np.array([
                features.get(name, 0.0) 
                for name in self.feature_extractor.get_feature_names()
            ])
            
            baseline_deviation, baseline_details = self.baseline_builder.calculate_deviation(
                user, feature_vector
            )
        
        # Combined anomaly score
        combined_score = (outlier_score * 0.6 + min(baseline_deviation / 5.0, 1.0) * 0.4)
        
        is_anomaly = combined_score > 0.5 or is_outlier
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": float(combined_score),
            "outlier_detection": {
                "is_outlier": is_outlier,
                "score": float(outlier_score),
                **outlier_details
            },
            "baseline_detection": {
                "deviation_score": float(baseline_deviation),
                **baseline_details
            },
            "event_summary": {
                "event_type": event.get("event_type"),
                "user": event.get("user"),
                "hostname": event.get("hostname"),
                "source_ip": event.get("source_ip"),
                "severity": event.get("severity")
            }
        }
    
    def detect_batch_anomalies(self, events: List[Dict]) -> List[Dict]:
        """Detect anomalies in batch"""
        results = []
        
        for event in events:
            result = self.detect_anomaly(event)
            results.append(result)
        
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        logger.info(f"Analyzed {len(events)} events, found {anomaly_count} anomalies")
        
        return results
    
    def get_detector_status(self) -> Dict:
        """Get detector status and info"""
        return {
            "detector": self.detector.get_model_info(),
            "baselines_count": len(self.baseline_builder.baselines),
            "baselines": list(self.baseline_builder.baselines.keys())
        }

# Singleton
anomaly_service = AnomalyService()
