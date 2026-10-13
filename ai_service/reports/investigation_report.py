from typing import Dict, List, Any
from datetime import datetime
import logging
import hashlib

from ai_service.mitre.correlator import mitre_correlator

logger = logging.getLogger(__name__)

class InvestigationReportGenerator:
    """Generate comprehensive investigation reports"""
    
    def generate_report(self, attack: Dict[str, Any], anomalies: List[Dict] = None) -> Dict[str, Any]:
        """
        Generate comprehensive investigation report
        
        Args:
            attack: Attack narrative from kill chain correlator
            anomalies: Related anomalies from ML detector
        
        Returns:
            Complete investigation report
        """
        
        report_id = hashlib.md5(f"{attack['attack_id']}{datetime.utcnow()}".encode()).hexdigest()[:8]
        
        # Extract IOCs
        iocs = self._extract_iocs(attack["events"])
        
        # Map to MITRE ATT&CK
        mitre_techniques = self._map_mitre_attack(attack)
        
        # Build timeline
        timeline = self._build_timeline(attack["events"])
        
        # Generate recommendations
        recommendations = self._generate_recommendations(attack, mitre_techniques)
        
        report = {
            "report_id": report_id,
            "generated_at": datetime.utcnow().isoformat(),
            "attack_summary": {
                "attack_id": attack["attack_id"],
                "source_ip": attack["source_ip"],
                "severity": attack["severity"],
                "confidence": attack["confidence"],
                "status": "active" if attack["severity"] in ["critical", "high"] else "investigation",
                "event_count": attack["event_count"],
                "affected_users": attack["affected_users"],
                "affected_hosts": attack["affected_hosts"],
                "time_span_minutes": attack["time_span"],
                "first_event": attack["first_event"],
                "last_event": attack["last_event"]
            },
            "kill_chain": {
                "stages_detected": attack["unique_stages"],
                "stage_progression": attack["stages"],
                "narrative": self._build_narrative(attack)
            },
            "indicators_of_compromise": iocs,
            "mitre_attack_mapping": mitre_techniques,
            "timeline": timeline,
            "affected_systems": {
                "users": attack["affected_users"],
                "hosts": attack["affected_hosts"],
                "unique_ips": list(set(e.get("destination_ip") for e in attack["events"] if e.get("destination_ip")))
            },
            "recommendations": recommendations,
            "next_steps": [
                "1. Isolate affected systems immediately",
                "2. Preserve forensic evidence",
                "3. Review all events from this source IP",
                "4. Check for lateral movement to other systems",
                "5. Monitor for data exfiltration",
                "6. Update detection rules based on findings"
            ]
        }
        
        logger.info(f"Generated investigation report {report_id}")
        return report
    
    @staticmethod
    def _extract_iocs(events: List[Dict]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from events"""
        iocs = {
            "ips": set(),
            "domains": set(),
            "file_hashes": set(),
            "process_names": set(),
            "file_paths": set()
        }
        
        for event in events:
            if event.get("source_ip"):
                iocs["ips"].add(event["source_ip"])
            if event.get("destination_ip"):
                iocs["ips"].add(event["destination_ip"])
            if event.get("process_name"):
                iocs["process_names"].add(event["process_name"])
            if event.get("file_hash"):
                iocs["file_hashes"].add(event["file_hash"])
            if event.get("file_path"):
                iocs["file_paths"].add(event["file_path"])
            if "metadata" in event and "query" in event["metadata"]:
                iocs["domains"].add(event["metadata"]["query"])
        
        return {k: list(v) for k, v in iocs.items()}
    
    def _map_mitre_attack(self, attack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map the events of the attack to MITRE ATT&CK techniques (dynamic).

        The technique catalogue comes from the official ATT&CK data
        (see ``ai_service.mitre``); nothing is hard-coded here.
        """
        return mitre_correlator.map_attack(attack)

    @staticmethod
    def _build_timeline(events: List[Dict]) -> List[Dict]:
        """Build chronological timeline of events"""
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        
        timeline = []
        for i, event in enumerate(sorted_events, 1):
            timeline.append({
                "sequence": i,
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "description": f"{event.get('event_type')} by {event.get('user', 'unknown')} on {event.get('hostname')}",
                "severity": event.get("severity", "low"),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "process": event.get("process_name"),
                "file": event.get("file_path")
            })
        
        return timeline
    
    @staticmethod
    def _build_narrative(attack: Dict) -> str:
        """Build human-readable attack narrative"""
        stages = attack.get("unique_stages", [])
        
        narrative = f"Attack detected from {attack['source_ip']} involving {len(attack['events'])} events over {attack['time_span']:.0f} minutes. "
        
        stage_descriptions = {
            "reconnaissance": "The attacker performed network reconnaissance",
            "exploitation": "The attacker exploited vulnerabilities",
            "persistence": "The attacker installed persistence mechanisms",
            "lateral_movement": "The attacker moved laterally within the network",
            "exfiltration": "The attacker exfiltrated data"
        }
        
        narrative += "Attack flow: " + " → ".join(stage_descriptions.get(s, s) for s in stages) + "."
        
        return narrative
    
    @staticmethod
    def _generate_recommendations(attack: Dict, techniques: List[Dict]) -> List[str]:
        """Generate recommendations based on attack"""
        recommendations = []
        
        severity = attack["severity"]
        stages = attack.get("unique_stages", [])
        
        if "exfiltration" in stages:
            recommendations.append("🚨 CRITICAL: Data exfiltration detected - immediately review data loss")
            recommendations.append("Block the destination IP at network perimeter")
            recommendations.append("Preserve all logs related to this incident")
        
        if "lateral_movement" in stages:
            recommendations.append("⚠️ Lateral movement detected - check all connected systems")
            recommendations.append("Review network segmentation policies")
            recommendations.append("Force credential reset for affected users")
        
        if "persistence" in stages:
            recommendations.append("Persistence mechanism detected - perform deep system scan")
            recommendations.append("Review scheduled tasks and autostart locations")
            recommendations.append("Check for unauthorized services")
        
        if "exploitation" in stages:
            recommendations.append("Exploitation detected - patch vulnerable systems")
            recommendations.append("Review system logs for successful exploitation")
            recommendations.append("Check for privilege escalation")
        
        recommendations.append(f"Implement detection rules for {len(techniques)} identified MITRE techniques")
        
        return recommendations

# Singleton
report_generator = InvestigationReportGenerator()
