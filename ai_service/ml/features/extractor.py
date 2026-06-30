import pandas as pd
import numpy as np
from typing import Dict, List, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract ML features from security events for anomaly detection"""
    
    # Suspicious process indicators
    SUSPICIOUS_PROCESSES = [
        "powershell", "cmd", "certutil", "psexec", "wmiexec",
        "rundll32", "regsvcs", "regasm", "InstallUtil", "mshta"
    ]
    
    # Sensitive file paths
    SENSITIVE_PATHS = [
        "finance", "hr", "confidential", "secret", "passwords",
        "salary", "budget", "private", "admin"
    ]
    
    # High-risk ports
    HIGH_RISK_PORTS = [22, 3389, 445, 135, 139, 111]
    
    @staticmethod
    def extract_event_features(event: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract numerical features from a single security event
        
        Returns dict of feature_name -> value
        """
        features = {}
        
        # ============ TIME-BASED FEATURES ============
        if "timestamp" in event and event.get("timestamp"):
            try:
                ts_str = event["timestamp"]
                if isinstance(ts_str, str):
                    ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                else:
                    ts = ts_str
                features["hour_of_day"] = float(ts.hour)
                features["day_of_week"] = float(ts.weekday())
                features["is_business_hours"] = 1.0 if 8 <= ts.hour <= 18 else 0.0
                features["is_weekend"] = 1.0 if ts.weekday() >= 5 else 0.0
            except Exception as e:
                logger.debug(f"Error extracting time features: {e}")
                features["hour_of_day"] = 12.0
                features["day_of_week"] = 3.0
                features["is_business_hours"] = 0.5
                features["is_weekend"] = 0.0
        else:
            features["hour_of_day"] = 12.0
            features["day_of_week"] = 3.0
            features["is_business_hours"] = 0.5
            features["is_weekend"] = 0.0
        
        # ============ NETWORK FEATURES ============
        dest_port = event.get("destination_port")
        if dest_port is not None:
            try:
                features["destination_port"] = float(dest_port)
                features["is_high_risk_port"] = 1.0 if int(dest_port) in FeatureExtractor.HIGH_RISK_PORTS else 0.0
            except (ValueError, TypeError):
                features["destination_port"] = 443.0
                features["is_high_risk_port"] = 0.0
        else:
            features["destination_port"] = 443.0
            features["is_high_risk_port"] = 0.0
        
        source_ip = event.get("source_ip")
        if source_ip:
            try:
                features["is_internal_source"] = 1.0 if str(source_ip).startswith(("192.168", "10.", "172.")) else 0.0
            except:
                features["is_internal_source"] = 0.0
        else:
            features["is_internal_source"] = 1.0
        
        dest_ip = event.get("destination_ip")
        if dest_ip:
            try:
                is_internal = str(dest_ip).startswith(("192.168", "10.", "172."))
                features["is_internal_dest"] = 1.0 if is_internal else 0.0
                features["is_external_dest"] = 0.0 if is_internal else 1.0
            except:
                features["is_internal_dest"] = 0.0
                features["is_external_dest"] = 0.0
        else:
            features["is_internal_dest"] = 0.0
            features["is_external_dest"] = 0.0
        
        # ============ PROCESS FEATURES ============
        process_name = event.get("process_name")
        if process_name:
            try:
                proc_str = str(process_name).lower()
                features["is_suspicious_process"] = 1.0 if any(p in proc_str for p in FeatureExtractor.SUSPICIOUS_PROCESSES) else 0.0
                features["process_name_length"] = float(len(proc_str))
            except:
                features["is_suspicious_process"] = 0.0
                features["process_name_length"] = 0.0
        else:
            features["is_suspicious_process"] = 0.0
            features["process_name_length"] = 0.0
        
        command_line = event.get("command_line")
        if command_line:
            try:
                cmd = str(command_line).lower()
                features["command_line_length"] = float(len(cmd))
                features["has_encoded_command"] = 1.0 if "-enc" in cmd or "-e " in cmd else 0.0
                features["has_obfuscation"] = 1.0 if any(x in cmd for x in ["|", "base64", "encode"]) else 0.0
                features["has_url"] = 1.0 if "http" in cmd else 0.0
            except:
                features["command_line_length"] = 0.0
                features["has_encoded_command"] = 0.0
                features["has_obfuscation"] = 0.0
                features["has_url"] = 0.0
        else:
            features["command_line_length"] = 0.0
            features["has_encoded_command"] = 0.0
            features["has_obfuscation"] = 0.0
            features["has_url"] = 0.0
        
        # ============ FILE FEATURES ============
        file_path = event.get("file_path")
        if file_path:
            try:
                path_str = str(file_path).lower()
                features["is_sensitive_file"] = 1.0 if any(s in path_str for s in FeatureExtractor.SENSITIVE_PATHS) else 0.0
                features["file_path_length"] = float(len(path_str))
                features["is_executable"] = 1.0 if path_str.endswith(('.exe', '.dll', '.sys', '.bat', '.cmd')) else 0.0
            except:
                features["is_sensitive_file"] = 0.0
                features["file_path_length"] = 0.0
                features["is_executable"] = 0.0
        else:
            features["is_sensitive_file"] = 0.0
            features["file_path_length"] = 0.0
            features["is_executable"] = 0.0
        
        features["has_file_hash"] = 1.0 if event.get("file_hash") else 0.0
        
        # ============ THREAT INTEL FEATURES ============
        threat_intel = event.get("threat_intel", {})
        
        # Source IP threat score
        if threat_intel and "source_ip" in threat_intel:
            source_ti = threat_intel["source_ip"]
            if isinstance(source_ti, dict):
                features["source_ip_threat_score"] = float(source_ti.get("reputation_score", 0))
                features["source_ip_is_malicious"] = 1.0 if source_ti.get("is_malicious", False) else 0.0
            else:
                features["source_ip_threat_score"] = 0.0
                features["source_ip_is_malicious"] = 0.0
        else:
            features["source_ip_threat_score"] = 0.0
            features["source_ip_is_malicious"] = 0.0
        
        # Destination IP threat score
        if threat_intel and "destination_ip" in threat_intel:
            dest_ti = threat_intel["destination_ip"]
            if isinstance(dest_ti, dict):
                features["dest_ip_threat_score"] = float(dest_ti.get("reputation_score", 0))
                features["dest_ip_is_malicious"] = 1.0 if dest_ti.get("is_malicious", False) else 0.0
            else:
                features["dest_ip_threat_score"] = 0.0
                features["dest_ip_is_malicious"] = 0.0
        else:
            features["dest_ip_threat_score"] = 0.0
            features["dest_ip_is_malicious"] = 0.0
        
        # ============ EVENT TYPE FEATURES ============
        event_type = event.get("event_type")
        if event_type:
            try:
                et_str = str(event_type).lower()
                features["is_privilege_escalation"] = 1.0 if "privilege" in et_str or "escalat" in et_str else 0.0
                features["is_lateral_movement"] = 1.0 if "lateral" in et_str or "psexec" in et_str else 0.0
                features["is_file_access"] = 1.0 if "file" in et_str else 0.0
                features["is_process_execution"] = 1.0 if "process" in et_str else 0.0
                features["is_network_connection"] = 1.0 if "network" in et_str or "connection" in et_str else 0.0
            except:
                features["is_privilege_escalation"] = 0.0
                features["is_lateral_movement"] = 0.0
                features["is_file_access"] = 0.0
                features["is_process_execution"] = 0.0
                features["is_network_connection"] = 0.0
        else:
            features["is_privilege_escalation"] = 0.0
            features["is_lateral_movement"] = 0.0
            features["is_file_access"] = 0.0
            features["is_process_execution"] = 0.0
            features["is_network_connection"] = 0.0
        
        # ============ SEVERITY FEATURES ============
        severity = event.get("severity")
        if severity:
            try:
                severity_str = str(severity).lower()
                severity_map = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
                features["severity_score"] = severity_map.get(severity_str, 1.0)
            except:
                features["severity_score"] = 1.0
        else:
            features["severity_score"] = 1.0
        
        return features
    
    @staticmethod
    def extract_batch_features(events: List[Dict[str, Any]]) -> tuple:
        """
        Extract features from multiple events
        
        Returns:
        - X: numpy array of shape (n_events, n_features)
        - feature_names: list of feature names
        - events: original events with features attached
        """
        feature_list = []
        feature_names = None
        
        for event in events:
            features = FeatureExtractor.extract_event_features(event)
            
            if feature_names is None:
                feature_names = list(features.keys())
            
            feature_vector = [features.get(name, 0.0) for name in feature_names]
            feature_list.append(feature_vector)
            
            # Attach features to event for later reference
            event["_features"] = features
        
        X = np.array(feature_list, dtype=np.float32)
        
        logger.info(f"Extracted {len(events)} events with {len(feature_names)} features")
        return X, feature_names, events
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """Get all possible feature names in order"""
        sample_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.1",
            "destination_ip": "8.8.8.8",
            "destination_port": 443,
            "process_name": "explorer.exe",
            "command_line": "explorer.exe",
            "file_path": "C:\\Windows\\explorer.exe",
            "event_type": "process_execution",
            "severity": "low",
            "threat_intel": {}
        }
        features = FeatureExtractor.extract_event_features(sample_event)
        return list(features.keys())

# Singleton
feature_extractor = FeatureExtractor()
