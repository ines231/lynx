from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class RiskTreatment:
    """
    Recommend treatment decisions based on FAIR risk analysis
    
    Four treatment options:
    1. Remediate: Reduce threat/vulnerability (patches, hardening)
    2. Mitigate: Reduce loss magnitude (segmentation, controls)
    3. Accept: Tolerate the risk (low impact, monitor)
    4. Transfer: Share/avoid risk (insurance, outsource)
    """
    
    REMEDIATION_CONTROLS = {
        "privilege_escalation": [
            "Patch OS/applications immediately",
            "Implement privilege access management (PAM)",
            "Enable UAC/sudo audit logging",
            "Monitor privilege escalation attempts"
        ],
        "lateral_movement": [
            "Implement network segmentation",
            "Enforce MFA on all systems",
            "Monitor and restrict lateral movement tools (psexec, wmi)",
            "Conduct credential reset for affected users"
        ],
        "exfiltration": [
            "Block external IP at firewall",
            "Isolate affected systems",
            "Review data loss prevention (DLP) rules",
            "Check for ongoing data transfer",
            "Notify stakeholders of potential data breach"
        ],
        "persistence": [
            "Scan systems for suspicious tasks/services",
            "Review registry for autostart modifications",
            "Investigate unexpected scheduled tasks",
            "Remove unauthorized persistence mechanisms"
        ],
        "exploitation": [
            "Apply security patches immediately",
            "Disable vulnerable services",
            "Implement Web Application Firewall (WAF) rules",
            "Review vulnerability scanning results"
        ]
    }
    
    MITIGATION_CONTROLS = {
        "high_privilege_access": [
            "Implement just-in-time (JIT) access",
            "Enable MFA for admin accounts",
            "Segregate admin credentials",
            "Monitor admin activity closely"
        ],
        "data_access": [
            "Implement Data Loss Prevention (DLP)",
            "Encrypt sensitive data at rest and in transit",
            "Monitor access to sensitive files",
            "Restrict file sharing to approved channels"
        ],
        "network_access": [
            "Implement zero-trust architecture",
            "Enable network segmentation",
            "Restrict outbound connections",
            "Monitor unusual network traffic"
        ]
    }
    
    def recommend_treatment(self, risk_metrics: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate treatment recommendation based on risk metrics
        """
        ale = risk_metrics.get("annual_loss_expectancy", 0)
        var_95 = risk_metrics.get("value_at_risk_95", 0)
        tef = risk_metrics.get("threat_event_frequency", 0)
        vulnerability = risk_metrics.get("vulnerability", 0)
        plm = risk_metrics.get("probable_loss_magnitude", 0)
        
        event_type = event.get("event_type", "").lower()
        
        # Determine primary treatment strategy
        if ale > 50000 or var_95 > 150000:
            treatment_strategy = "REMEDIATE_URGENT"
            priority = "CRITICAL"
            timeline = "Immediately (< 4 hours)"
        elif ale > 20000 or var_95 > 75000:
            treatment_strategy = "REMEDIATE"
            priority = "HIGH"
            timeline = "Within 24-48 hours"
        elif ale > 10000:
            treatment_strategy = "MITIGATE"
            priority = "MEDIUM"
            timeline = "Within 1 week"
        elif ale > 5000:
            treatment_strategy = "MITIGATE_OR_ACCEPT"
            priority = "LOW"
            timeline = "Within 30 days"
        else:
            treatment_strategy = "ACCEPT"
            priority = "INFO"
            timeline = "Ongoing monitoring"
        
        # Get specific controls
        controls = self._get_controls_for_event(event_type, treatment_strategy)
        
        # Risk reduction targets
        if treatment_strategy in ["REMEDIATE", "REMEDIATE_URGENT"]:
            # Goal: Reduce TEF and vulnerability
            tef_reduction_target = tef * 0.3  # Reduce by 70%
            v_reduction_target = vulnerability * 0.4  # Reduce by 60%
            target_ale = ale * 0.15
        elif treatment_strategy == "MITIGATE":
            # Goal: Reduce loss magnitude
            plm_reduction_target = plm * 0.5  # Reduce by 50%
            target_ale = ale * 0.4
        else:
            target_ale = ale
        
        return {
            "treatment_strategy": treatment_strategy,
            "priority": priority,
            "implementation_timeline": timeline,
            "executive_summary": self._generate_executive_summary(ale, priority, event),
            "risk_metrics": {
                "current_annual_loss_expectancy": float(ale),
                "current_value_at_risk_95": float(var_95),
                "target_annual_loss_expectancy": float(target_ale),
                "risk_reduction_target": f"{(1 - target_ale/ale)*100:.1f}%" if ale > 0 else "N/A"
            },
            "recommended_controls": controls,
            "risk_components_to_address": self._identify_risk_drivers(tef, vulnerability, plm),
            "success_criteria": self._define_success_criteria(treatment_strategy, event_type),
            "follow_up_actions": [
                "1. Implement recommended controls within timeline",
                "2. Re-assess risk after implementation",
                "3. Validate control effectiveness",
                "4. Update threat hunting rules based on findings",
                "5. Schedule follow-up review"
            ]
        }
    
    def _get_controls_for_event(self, event_type: str, strategy: str) -> List[str]:
        """Get specific controls for event type and strategy"""
        controls = []
        
        # Add remediation controls if applicable
        for key, remediation_controls in self.REMEDIATION_CONTROLS.items():
            if key in event_type or (key == "exploitation" and "exploit" in event_type):
                controls.extend(remediation_controls)
        
        # Add mitigation controls
        if "privilege" in event_type or "escalat" in event_type:
            controls.extend(self.MITIGATION_CONTROLS["high_privilege_access"])
        elif "exfil" in event_type or "transfer" in event_type:
            controls.extend(self.MITIGATION_CONTROLS["data_access"])
        elif "network" in event_type or "lateral" in event_type:
            controls.extend(self.MITIGATION_CONTROLS["network_access"])
        
        return list(set(controls))  # Remove duplicates
    
    @staticmethod
    def _identify_risk_drivers(tef: float, vulnerability: float, plm: float) -> Dict[str, str]:
        """Identify which components drive risk"""
        drivers = {}
        
        # Normalize to 0-1 for comparison
        total = tef + vulnerability + plm
        if total > 0:
            tef_pct = (tef / total) * 100
            v_pct = (vulnerability / total) * 100
            plm_pct = (plm / total) * 100
        else:
            tef_pct = v_pct = plm_pct = 33
        
        if tef_pct > 40:
            drivers["threat_frequency"] = f"Threat events too frequent ({tef_pct:.0f}% of risk). Remediate by reducing threat surface."
        if v_pct > 40:
            drivers["vulnerability"] = f"Vulnerability too high ({v_pct:.0f}% of risk). Remediate by patching/hardening."
        if plm_pct > 40:
            drivers["loss_magnitude"] = f"Loss magnitude too high ({plm_pct:.0f}% of risk). Mitigate by segmentation/controls."
        
        return drivers
    
    @staticmethod
    def _define_success_criteria(strategy: str, event_type: str) -> List[str]:
        """Define how to measure success"""
        if strategy in ["REMEDIATE", "REMEDIATE_URGENT"]:
            return [
                "Controls deployed and validated within timeline",
                "No additional events of this type within 30 days",
                "Risk metrics reduced to target level",
                "Threat Event Frequency reduced by ≥50%",
                "Vulnerability score reduced by ≥50%"
            ]
        elif strategy == "MITIGATE":
            return [
                "Compensating controls implemented",
                "Data loss magnitude reduced by ≥50%",
                "Detection capability improved",
                "No escalation to further stages",
                "Risk within acceptable threshold"
            ]
        else:
            return [
                "Risk regularly monitored",
                "No material change in risk profile",
                "Early warning system in place",
                "Baseline maintained"
            ]
    
    @staticmethod
    def _generate_executive_summary(ale: float, priority: str, event: Dict) -> str:
        """Generate business-friendly summary"""
        event_type = event.get("event_type", "Unknown")
        source = event.get("source_ip", "Unknown")
        affected = event.get("affected_users", ["Unknown"])[0] if event.get("affected_users") else "Unknown"
        
        summary = f"{priority} PRIORITY: {event_type.replace('_', ' ').title()}\n"
        summary += f"Expected Annual Loss: ${ale:,.0f}\n"
        summary += f"Affected: {affected} from {source}\n"
        
        if priority in ["CRITICAL", "HIGH"]:
            summary += "Immediate action required to reduce organizational risk."
        elif priority == "MEDIUM":
            summary += "Implement controls within 1 week to manage risk effectively."
        else:
            summary += "Continue monitoring; risk is within acceptable levels."
        
        return summary

# Singleton
risk_treatment = RiskTreatment()
