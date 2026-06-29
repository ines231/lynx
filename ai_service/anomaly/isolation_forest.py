import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.is_fitted = False
        self.feature_names = []
    
    def train(self, baseline_data: np.ndarray, feature_names: List[str]):
        """Train the Isolation Forest model on baseline data"""
        logger.info(f"Training Isolation Forest on {len(baseline_data)} samples")
        self.feature_names = feature_names
        self.model.fit(baseline_data)
        self.is_fitted = True
        logger.info("Model training complete")
    
    def detect_anomalies(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """Detect if a feature vector is anomalous"""
        if not self.is_fitted:
            logger.warning("Model not fitted yet")
            return False, 0.0
        
        feature_vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ]).reshape(1, -1)
        
        prediction = self.model.predict(feature_vector)[0]
        anomaly_score = -self.model.score_samples(feature_vector)[0]
        
        is_anomaly = prediction == -1
        
        return is_anomaly, float(anomaly_score)
    
    def save_model(self, path: str):
        """Save trained model to disk"""
        joblib.dump(self.model, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """Load trained model from disk"""
        self.model = joblib.load(path)
        self.is_fitted = True
        logger.info(f"Model loaded from {path}")
