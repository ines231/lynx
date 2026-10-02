import numpy as np
import pandas as pd
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class BaselineModel:
    """Build statistical baselines for normal behavior per user/system."""

    def __init__(self, window_days: int = 90):
        self.window_days = window_days
        self.user_baselines = {}
        self.system_baselines = {}
        self.global_baseline = {}

    @staticmethod
    def _get_value(event: Any, key: str, default=None):
        """
        Read a field from either a dictionary or a Pydantic/model object.
        This keeps the baseline compatible with SecurityEvent and dict events.
        """
        if isinstance(event, dict):
            return event.get(key, default)

        return getattr(event, key, default)

    def build_user_baseline(
        self,
        user: str,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Build comprehensive statistical baseline for a user."""

        if not events:
            logger.warning(f"No events for user {user}")
            return {}

        baseline = {
            "user": user,
            "event_count": len(events),
            "time_patterns": self._analyze_time_patterns(events),
            "process_patterns": self._analyze_process_patterns(events),
            "network_patterns": self._analyze_network_patterns(events),
            "file_patterns": self._analyze_file_patterns(events),
            "severity_distribution": self._analyze_severity_distribution(events),
        }

        self.user_baselines[user] = baseline

        logger.info(
            f"Built baseline for user {user}: {len(events)} events"
        )

        return baseline

    def build_system_baseline(
        self,
        hostname: str,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Build baseline for a specific system."""

        if not events:
            return {}

        baseline = {
            "hostname": hostname,
            "event_count": len(events),
            "event_types": self._get_distribution(events, "event_type"),
            "users": self._get_distribution(events, "user"),
            "processes": self._get_distribution(events, "process_name"),
            "ports": self._get_distribution(events, "destination_port"),
            "severity_profile": self._get_distribution(events, "severity"),
        }

        self.system_baselines[hostname] = baseline

        logger.info(f"Built baseline for system {hostname}")

        return baseline

    def _analyze_time_patterns(
        self,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Analyze when user is typically active."""

        hours = []
        days = []

        for event in events:
            try:
                from datetime import datetime

                timestamp = self._get_value(event, "timestamp", "")

                if not timestamp:
                    continue

                if hasattr(timestamp, "hour"):
                    ts = timestamp
                else:
                    ts = datetime.fromisoformat(
                        str(timestamp).replace("Z", "+00:00")
                    )

                hours.append(ts.hour)
                days.append(ts.weekday())

            except (ValueError, TypeError, AttributeError):
                continue

        if not hours:
            return {
                "active_hours": list(range(9, 18)),
                "active_days": list(range(5)),
                "hour_mean": 13.0,
                "hour_std": 2.5,
                "typical_business_hours": True,
            }

        hour_dist = pd.Series(hours).value_counts()
        day_dist = pd.Series(days).value_counts()

        return {
            "active_hours": sorted(
                hour_dist.head(5).index.tolist()
            ),
            "active_days": sorted(
                day_dist.index.tolist()
            ),
            "hour_mean": float(np.mean(hours)),
            "hour_std": float(np.std(hours)),
            "typical_business_hours": (
                self._is_typical_business_hours(hours)
            ),
        }

    def _analyze_process_patterns(
        self,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Analyze typical processes used by user."""

        processes = [
            self._get_value(event, "process_name")
            for event in events
            if self._get_value(event, "process_name")
        ]

        if not processes:
            return {
                "typical_processes": [],
                "process_count": 0
            }

        proc_dist = pd.Series(processes).value_counts()

        return {
            "typical_processes": proc_dist.head(10).index.tolist(),
            "process_count": len(set(processes)),
            "most_common": (
                proc_dist.index[0]
                if len(proc_dist) > 0
                else None
            ),
            "frequency_distribution": proc_dist.head(5).to_dict(),
        }

    def _analyze_network_patterns(
        self,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Analyze typical network destinations and ports."""

        ports = [
            self._get_value(event, "destination_port")
            for event in events
            if self._get_value(event, "destination_port")
        ]

        ips = [
            self._get_value(event, "destination_ip")
            for event in events
            if self._get_value(event, "destination_ip")
        ]

        return {
            "typical_ports": (
                pd.Series(ports)
                .value_counts()
                .head(5)
                .index
                .tolist()
                if ports
                else []
            ),
            "typical_destinations": (
                pd.Series(ips)
                .value_counts()
                .head(5)
                .index
                .tolist()
                if ips
                else []
            ),
            "port_mean": (
                float(np.mean(ports))
                if ports
                else 0.0
            ),
            "port_std": (
                float(np.std(ports))
                if ports
                else 0.0
            ),
        }

    def _analyze_file_patterns(
        self,
        events: List[Any]
    ) -> Dict[str, Any]:
        """Analyze typical files accessed by user."""

        files = [
            self._get_value(event, "file_path")
            for event in events
            if self._get_value(event, "file_path")
        ]

        if not files:
            return {
                "file_count": 0,
                "typical_files": []
            }

        file_dist = pd.Series(files).value_counts()

        return {
            "file_count": len(set(files)),
            "typical_files": file_dist.head(10).index.tolist(),
            "sensitive_files_accessed": sum(
                1
                for file_path in files
                if any(
                    keyword in str(file_path).lower()
                    for keyword in [
                        "confidential",
                        "secret",
                        "finance",
                        "hr",
                    ]
                )
            ),
        }

    def _analyze_severity_distribution(
        self,
        events: List[Any]
    ) -> Dict[str, int]:
        """Analyze distribution of event severities."""

        severities = [
            self._get_value(event, "severity", "low")
            for event in events
        ]

        sev_dist = pd.Series(severities).value_counts()

        return {
            "low": int(sev_dist.get("low", 0)),
            "medium": int(sev_dist.get("medium", 0)),
            "high": int(sev_dist.get("high", 0)),
            "critical": int(sev_dist.get("critical", 0)),
        }

    @staticmethod
    def _get_distribution(
        events: List[Any],
        key: str
    ) -> Dict[str, int]:
        """Get value distribution for a key."""

        values = [
            BaselineModel._get_value(event, key)
            for event in events
            if BaselineModel._get_value(event, key)
        ]

        if not values:
            return {}

        dist = pd.Series(values).value_counts()

        return {
            str(key_value): int(count)
            for key_value, count in dist.head(10).items()
        }

    @staticmethod
    def _is_typical_business_hours(
        hours: List[int]
    ) -> bool:
        """Check if user is typically active during business hours."""

        if not hours:
            return True

        business_hours = [
            hour for hour in hours
            if 8 <= hour <= 18
        ]

        return len(business_hours) / len(hours) > 0.8

    def get_user_baseline(
        self,
        user: str
    ) -> Dict[str, Any]:
        """Retrieve baseline for user."""

        return self.user_baselines.get(user, {})

    def get_system_baseline(
        self,
        hostname: str
    ) -> Dict[str, Any]:
        """Retrieve baseline for system."""

        return self.system_baselines.get(hostname, {})


# Singleton
baseline_model = BaselineModel()
