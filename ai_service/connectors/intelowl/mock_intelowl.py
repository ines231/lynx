from ai_service.connectors.models.event import ThreatIntelResult
from typing import Optional
from datetime import datetime
import random
import logging

logger = logging.getLogger(__name__)

class MockIntelOwlConnector:
    """
    Mock IntelOwl connector that simulates threat intelligence responses
    without requiring actual IntelOwl instance
    """
    
    def __init__(self):
        # Known malicious IPs
        self.malicious_ips = [
            "203.0.113.45", "198.51.100.50", "192.0.2.100",
            "198.51.100.200", "203.0.113.150"
        ]
        
        # Known malicious domains
        self.malicious_domains = [
            "malware-distribution.com", "c2-server.net", "phishing-site.org",
            "exploit-kit.ru", "botnet-controller.xyz"
        ]
        
        # Known malicious hashes
        self.malicious_hashes = [
            "666" + "0" * 61,  # Fake but consistent for testing
            "999" + "1" * 61
        ]
    
    async def check_ip(self, ip: str) -> ThreatIntelResult:
        """Check IP reputation"""
        is_malicious = ip in self.malicious_ips or random.random() < 0.15
        
        result = ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            reputation_score=float(random.randint(60, 95)) if is_malicious else float(random.randint(1, 20)),
            is_malicious=is_malicious,
            source="mock_intelowl",
            details={
                "country": random.choice(["Unknown", "RU", "CN", "KP", "IR"]),
                "asn": f"AS{random.randint(1000, 65000)}",
                "reports": random.randint(0, 50) if is_malicious else 0,
                "last_analysis": "high" if is_malicious else "clean"
            }
        )
        
        logger.debug(f"IntelOwl check for IP {ip}: {result.is_malicious}")
        return result
    
    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """Check domain reputation"""
        is_malicious = domain in self.malicious_domains or "malware" in domain.lower()
        
        result = ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            reputation_score=float(random.randint(70, 95)) if is_malicious else float(random.randint(1, 15)),
            is_malicious=is_malicious,
            source="mock_intelowl",
            details={
                "age_days": random.randint(1, 3650),
                "registrar": random.choice(["GoDaddy", "Namecheap", "Unknown"]),
                "dns_records": ["A", "MX", "NS"],
                "categories": ["malware", "phishing"] if is_malicious else ["legitimate", "safe"]
            }
        )
        
        logger.debug(f"IntelOwl check for domain {domain}: {result.is_malicious}")
        return result
    
    async def check_hash(self, file_hash: str) -> ThreatIntelResult:
        """Check file hash reputation"""
        is_malicious = file_hash in self.malicious_hashes or file_hash.startswith("666")
        
        result = ThreatIntelResult(
            indicator=file_hash,
            indicator_type="hash",
            reputation_score=float(random.randint(80, 99)) if is_malicious else float(random.randint(0, 5)),
            is_malicious=is_malicious,
            source="mock_intelowl",
            details={
                "detections": random.randint(20, 60) if is_malicious else 0,
                "vendors": ["Kaspersky", "McAfee", "Symantec"] if is_malicious else [],
                "file_type": random.choice(["exe", "dll", "sys", "bat"]),
                "file_size": random.randint(1024, 10485760)
            }
        )
        
        logger.debug(f"IntelOwl check for hash {file_hash[:16]}...: {result.is_malicious}")
        return result
    
    async def check_url(self, url: str) -> ThreatIntelResult:
        """Check URL reputation"""
        is_malicious = any(domain in url for domain in self.malicious_domains)
        
        result = ThreatIntelResult(
            indicator=url,
            indicator_type="url",
            reputation_score=float(random.randint(60, 95)) if is_malicious else float(random.randint(1, 20)),
            is_malicious=is_malicious,
            source="mock_intelowl",
            details={
                "http_code": 200 if not is_malicious else 404,
                "content_type": "text/html",
                "redirects": ["http://malware-cdn.com"] if is_malicious else []
            }
        )
        
        logger.debug(f"IntelOwl check for URL: {result.is_malicious}")
        return result

# Singleton instance
mock_intelowl = MockIntelOwlConnector()
