from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class SecurityEvent(BaseModel):
    """Base security event model"""
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    
    event_type: str  # login, process_execution, file_access, network, etc.
    user: Optional[str] = None
    hostname: Optional[str] = None
    
    # Process info
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    
    # File info
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Rule/Alert info
    rule_id: Optional[int] = None
    rule_description: Optional[str] = None
    severity: str = "low"  # low, medium, high, critical
    
    # Additional metadata
    metadata: Dict[str, Any] = {}
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-15T10:30:00Z",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.100",
                "event_type": "process_execution",
                "user": "admin",
                "hostname": "WORKSTATION-01",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -Command Get-ChildItem",
                "severity": "medium"
            }
        }

class ThreatIntelResult(BaseModel):
    """Threat intelligence check result"""
    indicator: str
    indicator_type: str  # ip, domain, hash
    reputation_score: float  # 0-100
    is_malicious: bool
    source: str  # mock_intelowl, real_intelowl
    details: Dict[str, Any] = {}
    checked_at: datetime = datetime.utcnow()

class EnrichedEvent(BaseModel):
    """Event enriched with threat intelligence"""
    event: SecurityEvent
    threat_intel: Dict[str, ThreatIntelResult] = {}
    anomaly_score: Optional[float] = None
    is_anomaly: bool = False
    kill_chain_stage: Optional[str] = None
