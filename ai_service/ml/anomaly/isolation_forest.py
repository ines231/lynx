import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Tuple, Optional
from ai_service.ml.features.extractor import FeatureExtractor
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class IsolationForestDetector:
    """Anomaly detector using Isolation Forest algorithm"""
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        """
        Initialize detector
        
        contamination: expected proportion of anomalies (0.1 = 10%)
        n_estimators: number of trees in forest
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = None
        self.is_fitted = False
        self.feature_names = []
        self.model_path = Path("data/models/isolation_forest.joblib")
    
    def train(self, events: List[Dict], feature_names: Optional[List[str]] = None) -> Dict:
        """
        Train the Isolation Forest model
        
        events: list of security events with _features attached
        feature_names: optional list of feature names (will extract if not provided)
        """
        if not events:
            logger.error("No events provided for training")
            return {"status": "error", "message": "No events provided"}
        
        # Extract features
        X, extracted_feature_names, _ = FeatureExtractor.extract_batch_features(events)
        
        self.feature_names = feature_names or extracted_feature_names
        
        logger.info(f"Training Isolation Forest on {len(events)} events with {X.shape[1]} features")
        
        # Create and train model
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X)
        self.is_fitted = True
        
        logger.info("Isolation Forest training complete")
        
        return {
            "status": "success",
            "events_trained": len(events),
            "features": len(self.feature_names),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators
        }
    
    def detect_anomaly(self, event: Dict) -> Tuple[bool, float, Dict]:
        """
        Detect if an event is anomalous
        
        Returns:
        - is_anomaly: bool
        - anomaly_score: float (0-1, higher = more anomalous)
        - details: dict with additional info
        """
        if not self.is_fitted:
            logger.warning("Model not trained yet")
            return False, 0.0, {"error": "Model not trained"}
        
        # Extract features
        features = FeatureExtractor.extract_event_features(event)
        feature_vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ]).reshape(1, -1)
        
        # Get predictions
        prediction = self.model.predict(feature_vector)[0]  # -1 = anomaly, 1 = normal
        anomaly_scores = self.model.score_samples(feature_vector)[0]
        
        # Normalize score to 0-1 range (higher = more anomalous)
        # score_samples returns negative scores for anomalies
        anomaly_score = 1.0 / (1.0 + np.exp(anomaly_scores))
        
        is_anomaly = prediction == -1
        
        details = {
            "prediction": int(prediction),
            "raw_score": float(anomaly_scores),
            "normalized_score": float(anomaly_score),
            "is_anomaly": is_anomaly,
            "event_type": event.get("event_type"),
            "user": event.get("user"),
            "hostname": event.get("hostname"),
            "source_ip": event.get("source_ip"),
        }
        
        if is_anomaly:
            logger.warning(f"Anomaly detected: {event.get('event_type')} from {event.get('user')} - score: {anomaly_score:.2f}")
        
        return is_anomaly, anomaly_score, details
    
    def detect_batch_anomalies(self, events: List[Dict]) -> List[Dict]:
        """Detect anomalies in batch of events"""
        results = []
        
        for event in events:
            is_anomaly, score, details = self.detect_anomaly(event)
            results.append({
                "is_anomaly": is_anomaly,
                "anomaly_score": score,
                **details
            })
        
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        logger.info(f"Processed {len(events)} events, found {anomaly_count} anomalies")
        
        return results
    
    def save_model(self, path: Optional[str] = None) -> str:
        """Save model to disk"""
        if not self.is_fitted:
            logger.error("Cannot save untrained model")
            return ""
        
        save_path = path or str(self.model_path)
        joblib.dump({
            "model": self.model,
            "feature_names": self.feature_names,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators
        }, save_path)
        
        logger.info(f"Model saved to {save_path}")
        return save_path
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model from disk"""
        load_path = path or str(self.model_path)
        
        try:
            data = joblib.load(load_path)
            self.model = data["model"]
            self.feature_names = data["feature_names"]
            self.contamination = data["contamination"]
            self.n_estimators = data["n_estimators"]
            self.is_fitted = True
            logger.info(f"Model loaded from {load_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_model_info(self) -> Dict:
        """Get information about the model"""
        return {
            "is_fitted": self.is_fitted,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names
        }

# Singleton
detector = IsolationForestDetector()
