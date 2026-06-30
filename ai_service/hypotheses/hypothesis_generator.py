from typing import List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class HypothesisGenerator:
    """Auto-generate hunting hypotheses based on threat patterns"""
    
    # Known attack patterns and corresponding hypotheses
    HYPOTHESIS_TEMPLATES = {
        "reconnaissance": [
            {
                "title": "Network Scanning",
                "description": "Attacker is scanning network for accessible systems",
                "hunt_keywords": ["port scan", "service enumeration", "network probe"],
                "indicators": [">10 failed connections to different ports", "DNS enumeration queries"],
                "ttps": ["T1046", "T1018"]
            },
            {
                "title": "Service Discovery",
                "description": "Attacker is discovering running services",
                "hunt_keywords": ["service", "enumerate", "discovery"],
                "indicators": ["Unusual connections to rare services", "Service enumeration tools"],
                "ttps": ["T1046"]
            }
        ],
        "exploitation": [
            {
                "title": "Privilege Escalation",
                "description": "Attacker is escalating privileges",
                "hunt_keywords": ["privilege", "escalat", "sudo", "run as admin"],
                "indicators": ["Non-admin user executing SYSTEM commands", "Unexpected privilege transitions"],
                "ttps": ["T1548"]
            },
            {
                "title": "Code Injection",
                "description": "Attacker is injecting malicious code",
                "hunt_keywords": ["inject", "dll", "shellcode", "process hollowing"],
                "indicators": ["DLL injection from suspicious location", "Unsigned DLLs loaded"],
                "ttps": ["T1055"]
            }
        ],
        "persistence": [
            {
                "title": "Scheduled Task Abuse",
                "description": "Attacker created scheduled tasks for persistence",
                "hunt_keywords": ["scheduled task", "cron", "schtasks"],
                "indicators": ["Suspicious scheduled task creation", "Tasks running unusual commands"],
                "ttps": ["T1053"]
            },
            {
                "title": "Registry Persistence",
                "description": "Attacker modified registry for persistence",
                "hunt_keywords": ["registry", "run key", "autorun"],
                "indicators": ["Run key modifications", "Startup folder changes"],
                "ttps": ["T1547"]
            }
        ],
        "lateral_movement": [
            {
                "title": "Credential Reuse",
                "description": "Attacker is reusing stolen credentials across systems",
                "hunt_keywords": ["credential", "reuse", "same password", "lateral"],
                "indicators": ["Same credential on multiple systems", "Impossible geography logins"],
                "ttps": ["T1078"]
            },
            {
                "title": "PsExec/WMI Movement",
                "description": "Attacker is using admin tools to move laterally",
                "hunt_keywords": ["psexec", "wmi", "winrm", "ssh"],
                "indicators": ["PsExec execution from unusual source", "Remote service execution"],
                "ttps": ["T1570"]
            }
        ],
        "exfiltration": [
            {
                "title": "Bulk Data Transfer",
                "description": "Attacker is exfiltrating large amounts of data",
                "hunt_keywords": ["transfer", "export", "upload", "exfil"],
                "indicators": [">1GB transfer to external IP", "Sensitive files accessed + external transfer"],
                "ttps": ["T1041"]
            },
            {
                "title": "Archive Before Exfil",
                "description": "Attacker created archives before exfiltration",
                "hunt_keywords": ["archive", "compress", "zip", "rar"],
                "indicators": ["Archive creation followed by transfer", "Unusual compression of sensitive data"],
                "ttps": ["T1560"]
            }
        ]
    }
    
    def generate_hypotheses_from_attack(self, attack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate hunting hypotheses based on detected attack
        
        Args:
            attack: Attack narrative from kill chain correlator
        
        Returns:
            List of hunting hypotheses
        """
        hypotheses = []
        stages = attack.get("unique_stages", [])
        
        for stage in stages:
            if stage in self.HYPOTHESIS_TEMPLATES:
                for template in self.HYPOTHESIS_TEMPLATES[stage]:
                    hypothesis = {
                        "hypothesis_id": self._generate_hypothesis_id(),
                        "generated_at": datetime.utcnow().isoformat(),
                        "stage": stage,
                        "title": template["title"],
                        "description": template["description"],
                        "hunt_keywords": template["hunt_keywords"],
                        "indicators": template["indicators"],
                        "mitre_techniques": template["ttps"],
                        "suggested_queries": self._build_hunt_queries(stage, template),
                        "confidence": attack["confidence"],
                        "status": "active"
                    }
                    hypotheses.append(hypothesis)
        
        logger.info(f"Generated {len(hypotheses)} hypotheses for attack {attack['attack_id']}")
        return hypotheses
    
    def generate_hypotheses_from_threat_intel(self, threat_type: str) -> List[Dict[str, Any]]:
        """
        Generate hunting hypotheses based on threat intelligence
        
        Examples: "ransomware", "apt", "insider_threat", "cryptominer"
        """
        hypotheses = []
        
        if threat_type == "ransomware":
            stages = ["reconnaissance", "exploitation", "persistence", "exfiltration"]
        elif threat_type == "apt":
            stages = ["reconnaissance", "exploitation", "persistence", "lateral_movement", "exfiltration"]
        elif threat_type == "insider_threat":
            stages = ["persistence", "lateral_movement", "exfiltration"]
        elif threat_type == "cryptominer":
            stages = ["exploitation", "persistence"]
        else:
            stages = []
        
        for stage in stages:
            if stage in self.HYPOTHESIS_TEMPLATES:
                template = self.HYPOTHESIS_TEMPLATES[stage][0]  # First hypothesis per stage
                hypothesis = {
                    "hypothesis_id": self._generate_hypothesis_id(),
                    "generated_at": datetime.utcnow().isoformat(),
                    "threat_type": threat_type,
                    "stage": stage,
                    "title": f"Hunting for {threat_type.replace('_', ' ')}: {template['title']}",
                    "description": template["description"],
                    "hunt_keywords": template["hunt_keywords"],
                    "indicators": template["indicators"],
                    "mitre_techniques": template["ttps"],
                    "suggested_queries": self._build_hunt_queries(stage, template),
                    "status": "active"
                }
                hypotheses.append(hypothesis)
        
        return hypotheses
    
    @staticmethod
    def _build_hunt_queries(stage: str, template: Dict) -> List[Dict[str, str]]:
        """Build suggested Wazuh/Elasticsearch queries for hypothesis"""
        queries = []
        
        if stage == "reconnaissance":
            queries.append({
                "name": "Port Scanning",
                "query": "event_type:port_scan | stats count by source_ip | where count > 10"
            })
            queries.append({
                "name": "DNS Enumeration",
                "query": "event_type:dns_query | regex query=internal.* | stats count by source_ip"
            })
        
        elif stage == "exploitation":
            queries.append({
                "name": "Privilege Escalation",
                "query": "event_type:privilege_escalation OR (process_name:powershell AND command_line:*Add-LocalGroupMember*)"
            })
            queries.append({
                "name": "Code Injection",
                "query": "process_name:explorer.exe OR process_name:svchost.exe | stats values(parent_process) by process_name"
            })
        
        elif stage == "persistence":
            queries.append({
                "name": "Scheduled Task Creation",
                "query": "event_type:scheduled_task OR command_line:*schtasks*"
            })
            queries.append({
                "name": "Registry Modifications",
                "query": "event_type:registry_modification AND (path:*Run OR path:*Startup)"
            })
        
        elif stage == "lateral_movement":
            queries.append({
                "name": "Credential Reuse",
                "query": "user:* | stats count by user, source_ip | where count > 1"
            })
            queries.append({
                "name": "PsExec Usage",
                "query": "process_name:psexec.exe OR command_line:*psexec* OR command_line:*wmiexec*"
            })
        
        elif stage == "exfiltration":
            queries.append({
                "name": "Large Data Transfer",
                "query": "bytes_transferred:>1000000000 AND destination_ip:!internal"
            })
            queries.append({
                "name": "Archive Creation + Transfer",
                "query": "(file_path:*.zip OR file_path:*.rar) followed by (event_type:network_connection AND destination_port:443)"
            })
        
        return queries
    
    @staticmethod
    def _generate_hypothesis_id() -> str:
        """Generate unique hypothesis ID"""
        import hashlib
        ts = datetime.utcnow().isoformat()
        return hashlib.md5(ts.encode()).hexdigest()[:8]

# Singleton
hypothesis_generator = HypothesisGenerator()
