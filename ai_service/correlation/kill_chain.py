from typing import Dict, List, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class KillChainCorrelation:
    """Correlate events across cyber kill chain stages."""

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
            "keywords": [
                "exploit",
                "privilege",
                "escalat",
                "inject",
                "privilege_escalation"
            ],
            "event_types": ["code_injection", "privilege_escalation"]
        },
        "persistence": {
            "keywords": [
                "run",
                "startup",
                "task",
                "service",
                "registry",
                "install"
            ],
            "event_types": [
                "registry_modification",
                "scheduled_task",
                "service_install"
            ]
        },
        "lateral_movement": {
            "keywords": [
                "psexec",
                "wmi",
                "cred",
                "share",
                "reuse",
                "lateral"
            ],
            "event_types": [
                "lateral_movement",
                "credential_use"
            ]
        },
        "exfiltration": {
            "keywords": [
                "transfer",
                "upload",
                "archive",
                "compress",
                "external"
            ],
            "event_types": [
                "data_transfer",
                "archive_creation",
                "file_access"
            ]
        }
    }

    def classify_stage(self, event: Dict[str, Any]) -> str:
        """Classify an event into a kill-chain stage."""

        event_str = str(event).lower()
        event_type = str(
            event.get("event_type", "")
        ).lower()

        for stage, rules in self.STAGE_RULES.items():
            if any(
                event_type_name in event_type
                for event_type_name in rules["event_types"]
            ):
                return stage

            if any(
                keyword in event_str
                for keyword in rules["keywords"]
            ):
                return stage

        return "unknown"

    def correlate_events(
        self,
        events: List[Dict[str, Any]],
        time_window_seconds: int = 3600
    ) -> List[Dict[str, Any]]:
        """
        Correlate related events across kill-chain stages.

        Events are correlated not only by source IP, but also through
        source -> destination continuity. This allows a scenario such as:

            attacker -> workstation -> server -> external destination

        to remain one investigation even when the source IP changes
        after lateral movement.
        """

        if not events:
            return []

        # ---------------------------------------------------------
        # 1. Classify and sort events chronologically
        # ---------------------------------------------------------

        classified_events = []

        for event in events:
            stage = self.classify_stage(event)

            classified_events.append({
                **event,
                "kill_chain_stage": stage
            })

        classified_events.sort(
            key=lambda event: self._timestamp_value(
                event.get("timestamp")
            )
        )

        # ---------------------------------------------------------
        # 2. Build correlated chains
        # ---------------------------------------------------------

        chains: List[List[Dict[str, Any]]] = []

        for event in classified_events:
            event_time = self._timestamp_value(
                event.get("timestamp")
            )

            source_ip = event.get("source_ip")
            matched_chain = None
            best_gap = None

            for chain in chains:
                if not chain:
                    continue

                last_event = chain[-1]

                last_time = self._timestamp_value(
                    last_event.get("timestamp")
                )

                gap = (
                    event_time - last_time
                ).total_seconds()

                if gap < 0 or gap > time_window_seconds:
                    continue

                last_source = last_event.get("source_ip")
                last_destination = last_event.get(
                    "destination_ip"
                )

                # Direct continuity:
                # same source OR the previous destination
                # becomes the new source after lateral movement.
                related = (
                    source_ip == last_source
                    or source_ip == last_destination
                )

                # Also allow the source to match any recent
                # destination in the chain.
                if not related:
                    chain_destinations = {
                        e.get("destination_ip")
                        for e in chain
                        if e.get("destination_ip")
                    }

                    related = source_ip in chain_destinations

                if related and (
                    best_gap is None
                    or gap < best_gap
                ):
                    matched_chain = chain
                    best_gap = gap

            if matched_chain is not None:
                matched_chain.append(event)
            else:
                chains.append([event])

        # ---------------------------------------------------------
        # 3. Convert chains into attack narratives
        # ---------------------------------------------------------

        attack_narratives = []

        for chain in chains:
            stages_seen = [
                event.get("kill_chain_stage")
                for event in chain
            ]

            unique_stage_set = set(stages_seen)

            # At least two different stages = potential attack.
            if len(unique_stage_set) < 2:
                continue

            ordered_unique_stages = [
                stage
                for stage in self.KILL_CHAIN_STAGES
                if stage in unique_stage_set
            ]

            source_ip = (
                chain[0].get("source_ip")
                or "unknown"
            )

            attack = {
                "attack_id": self._generate_attack_id(
                    source_ip
                ),
                "source_ip": source_ip,
                "events": chain,
                "stages": stages_seen,
                "unique_stages": ordered_unique_stages,
                "event_count": len(chain),
                "time_span": self._calculate_time_span(
                    chain
                ),
                "severity": self._calculate_severity(
                    stages_seen
                ),
                "confidence": self._calculate_confidence(
                    chain
                ),
                "affected_users": sorted(
                    set(
                        event.get("user")
                        for event in chain
                        if event.get("user")
                    )
                ),
                "affected_hosts": sorted(
                    set(
                        event.get("hostname")
                        for event in chain
                        if event.get("hostname")
                    )
                ),
                "first_event": (
                    chain[0].get("timestamp")
                    if chain
                    else None
                ),
                "last_event": (
                    chain[-1].get("timestamp")
                    if chain
                    else None
                ),
            }

            attack_narratives.append(attack)

        logger.info(
            "Found %s attack narratives",
            len(attack_narratives)
        )

        return sorted(
            attack_narratives,
            key=lambda attack: attack["confidence"],
            reverse=True
        )

    @staticmethod
    def _timestamp_value(value: Any) -> datetime:
        """
        Normalize datetime/string timestamps.

        Pydantic models commonly provide datetime objects while
        JSON payloads provide ISO strings. Supporting both avoids
        silently returning a 0-minute attack duration.
        """

        if isinstance(value, datetime):
            return value

        if value is None:
            return datetime.min

        try:
            return datetime.fromisoformat(
                str(value).replace(
                    "Z",
                    "+00:00"
                )
            )
        except (TypeError, ValueError):
            return datetime.min

    @staticmethod
    def _generate_attack_id(source_ip: str) -> str:
        """Generate a unique attack ID."""

        import hashlib

        timestamp = datetime.utcnow().isoformat()

        return hashlib.md5(
            f"{source_ip}{timestamp}".encode()
        ).hexdigest()[:12]

    @classmethod
    def _calculate_time_span(
        cls,
        events: List[Dict[str, Any]]
    ) -> float:
        """Calculate the attack time span in minutes."""

        if len(events) < 2:
            return 0.0

        first = cls._timestamp_value(
            events[0].get("timestamp")
        )

        last = cls._timestamp_value(
            events[-1].get("timestamp")
        )

        if (
            first == datetime.min
            or last == datetime.min
        ):
            return 0.0

        return max(
            0.0,
            (last - first).total_seconds() / 60.0
        )

    @staticmethod
    def _calculate_severity(
        stages: List[str]
    ) -> str:
        """Calculate severity based on kill-chain progression."""

        if "exfiltration" in stages:
            return "critical"

        if "lateral_movement" in stages:
            return "high"

        if "persistence" in stages:
            return "medium"

        if "exploitation" in stages:
            return "medium"

        return "low"

    @staticmethod
    def _calculate_confidence(
        events: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence score between 0 and 1."""

        if not events:
            return 0.0

        confidence = min(
            len(events) * 0.1,
            0.7
        )

        malicious_count = sum(
            1
            for event in events
            if (
                event.get(
                    "threat_intel",
                    {}
                )
                .get(
                    "source_ip",
                    {}
                )
                .get(
                    "is_malicious",
                    False
                )
            )
        )

        confidence += (
            malicious_count
            / max(len(events), 1)
        ) * 0.3

        return min(
            confidence,
            1.0
        )


# Singleton
kill_chain_correlator = KillChainCorrelation()
