from typing import Dict, List, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class KillChainCorrelation:
    """Correlate events across cyber kill chain stages"""
    
    KILL_CHAIN_STAGES = [
        "reconnaissance",
        "exploitation",
        "persistence",
        "lateral_movement",
        "exfiltration"
    ]
    
    STAGE_RULES = {
        "reconnaissance": {
            "keywords": ["scan", "enum", "dns", "probe"],
            "event_types": ["network_scan", "port_scan", "dns_query"]
        },
        "exploitation": {
            "keywords": ["exploit", "privilege", "escalat", "inject"],
            "event_types": ["code_injection", "privilege_escalation"]
        },
        "persistence": {
            "keywords": ["run", "startup", "task", "service", "registry"],
            "event_types": ["registry_modification", "scheduled_task", "service_install"]
        },
        "lateral_movement": {
            "keywords": ["psexec", "wmi", "cred", "share", "reuse"],
            "event_types": ["lateral_movement", "credential_use"]
        },
        "exfiltration": {
            "keywords": ["transfer", "upload", "archive", "compress", "external"],
            "event_types": ["data_transfer", "archive_creation"]
        }
    }
    
    def classify_stage(self, event: Dict[str, Any]) -> str:
        """Classify event into kill chain stage"""
        event_str = str(event).lower()
        event_type = event.get("event_type", "").lower()
        
        for stage, rules in self.STAGE_RULES.items():
            if any(et in event_type for et in rules["event_types"]):
                return stage
            if any(kw in event_str for kw in rules["keywords"]):
                return stage
        
        return "unknown"
    
    def correlate_events(self, events: List[Dict[str, Any]], time_window_seconds: int = 3600) -> List[Dict[str, Any]]:
        """Correlate related events across kill chain stages"""
        if not events:
            return []
        
        classified_events = []
        for event in events:
            stage = self.classify_stage(event)
            classified_events.append({**event, "kill_chain_stage": stage})
        
        attack_narratives = []
        by_source = {}
        
        for event in classified_events:
            source = event.get("source_ip", "unknown")
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(event)
        
        for source, source_events in by_source.items():
            sorted_events = sorted(
                source_events,
                key=lambda e: e.get("timestamp", "")
            )
            
            stages_seen = [e.get("kill_chain_stage") for e in sorted_events]
            
            if len(stages_seen) > 2:
                attack_narratives.append({
                    "source_ip": source,
                    "events": sorted_events,
                    "stages": stages_seen,
                    "time_span": self._calculate_time_span(sorted_events),
                    "severity": self._calculate_severity(stages_seen),
                    "confidence": self._calculate_confidence(sorted_events)
                })
        
        return attack_narratives
    
    @staticmethod
    def _calculate_time_span(events: List[Dict[str, Any]]) -> float:
        """Calculate time span in hours"""
        if len(events) < 2:
            return 0
        return 1.0
    
    @staticmethod
    def _calculate_severity(stages: List[str]) -> str:
        """Calculate severity based on kill chain progression"""
        if "exfiltration" in stages:
            return "critical"
        elif "lateral_movement" in stages:
            return "high"
        elif "persistence" in stages:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def _calculate_confidence(events: List[Dict[str, Any]]) -> float:
        """Calculate confidence score"""
        if not events:
            return 0.0
        
        confidence = min(len(events) * 0.15, 0.95)
        
        for event in events:
            if event.get("threat_intel", {}).get("source_ip", {}).get("is_malicious"):
                confidence += 0.1
        
        return min(confidence, 1.0)
