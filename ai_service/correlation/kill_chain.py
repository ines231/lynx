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
            "keywords": ["scan", "enum", "dns", "probe", "port_scan"],
            "event_types": ["network_scan", "port_scan", "dns_query"]
        },
        "exploitation": {
            "keywords": ["exploit", "privilege", "escalat", "inject", "privilege_escalation"],
            "event_types": ["code_injection", "privilege_escalation"]
        },
        "persistence": {
            "keywords": ["run", "startup", "task", "service", "registry", "install"],
            "event_types": ["registry_modification", "scheduled_task", "service_install"]
        },
        "lateral_movement": {
            "keywords": ["psexec", "wmi", "cred", "share", "reuse", "lateral"],
            "event_types": ["lateral_movement", "credential_use"]
        },
        "exfiltration": {
            "keywords": ["transfer", "upload", "archive", "compress", "external"],
            "event_types": ["data_transfer", "archive_creation", "file_access"]
        }
    }
    
    def classify_stage(self, event: Dict[str, Any]) -> str:
        """Classify event into kill chain stage"""
        event_str = str(event).lower()
        event_type = str(event.get("event_type", "")).lower()
        
        for stage, rules in self.STAGE_RULES.items():
            if any(et in event_type for et in rules["event_types"]):
                return stage
            if any(kw in event_str for kw in rules["keywords"]):
                return stage
        
        return "unknown"
    
    def correlate_events(self, events: List[Dict[str, Any]], time_window_seconds: int = 3600) -> List[Dict[str, Any]]:
        """
        Correlate related events across kill chain stages
        Returns list of attack narratives
        """
        if not events:
            return []
        
        # Classify each event
        classified_events = []
        for event in events:
            stage = self.classify_stage(event)
            classified_events.append({**event, "kill_chain_stage": stage})
        
        # Group by source IP
        attack_narratives = []
        by_source = {}
        
        for event in classified_events:
            source = event.get("source_ip", "unknown")
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(event)
        
        # Look for kill chain progressions
        for source, source_events in by_source.items():
            sorted_events = sorted(
                source_events,
                key=lambda e: e.get("timestamp", "")
            )
            
            stages_seen = [e.get("kill_chain_stage") for e in sorted_events]
            
            # At least 2 stages = potential attack
            if len(set(stages_seen)) >= 2:
                attack = {
                    "attack_id": self._generate_attack_id(source),
                    "source_ip": source,
                    "events": sorted_events,
                    "stages": stages_seen,
                    "unique_stages": list(set(stages_seen)),
                    "event_count": len(sorted_events),
                    "time_span": self._calculate_time_span(sorted_events),
                    "severity": self._calculate_severity(stages_seen),
                    "confidence": self._calculate_confidence(sorted_events),
                    "affected_users": list(set(e.get("user") for e in sorted_events if e.get("user"))),
                    "affected_hosts": list(set(e.get("hostname") for e in sorted_events if e.get("hostname"))),
                    "first_event": sorted_events[0].get("timestamp") if sorted_events else None,
                    "last_event": sorted_events[-1].get("timestamp") if sorted_events else None,
                }
                attack_narratives.append(attack)
        
        logger.info(f"Found {len(attack_narratives)} attack narratives")
        return sorted(attack_narratives, key=lambda x: x["confidence"], reverse=True)
    
    @staticmethod
    def _generate_attack_id(source_ip: str) -> str:
        """Generate unique attack ID"""
        import hashlib
        ts = datetime.utcnow().isoformat()
        return hashlib.md5(f"{source_ip}{ts}".encode()).hexdigest()[:12]
    
    @staticmethod
    def _calculate_time_span(events: List[Dict[str, Any]]) -> float:
        """Calculate time span in minutes"""
        if len(events) < 2:
            return 0.0
        
        try:
            first = datetime.fromisoformat(events[0]["timestamp"].replace('Z', '+00:00'))
            last = datetime.fromisoformat(events[-1]["timestamp"].replace('Z', '+00:00'))
            return (last - first).total_seconds() / 60.0
        except:
            return 0.0
    
    @staticmethod
    def _calculate_severity(stages: List[str]) -> str:
        """Calculate severity based on kill chain progression"""
        if "exfiltration" in stages:
            return "critical"
        elif "lateral_movement" in stages:
            return "high"
        elif "persistence" in stages:
            return "medium"
        elif "exploitation" in stages:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def _calculate_confidence(events: List[Dict[str, Any]]) -> float:
        """Calculate confidence score (0-1)"""
        if not events:
            return 0.0
        
        confidence = min(len(events) * 0.1, 0.7)
        
        # Increase confidence if events have high TI scores
        malicious_count = sum(
            1 for event in events 
            if event.get("threat_intel", {}).get("source_ip", {}).get("is_malicious", False)
        )
        confidence += (malicious_count / max(len(events), 1)) * 0.3
        
        return min(confidence, 1.0)

# Singleton
kill_chain_correlator = KillChainCorrelation()
