"""
MITRE ATT&CK knowledge base, loaded from the official STIX data.

Source
------
MITRE publishes ATT&CK as open STIX 2.1 bundles (no API key, no account):
``mitre-attack/attack-stix-data`` on GitHub. The Enterprise bundle weighs
about 50 MB, so it is downloaded once and reduced to a small JSON cache
(techniques only: id, name, summary, tactics, url, platforms), stored in
``data/mitre/techniques.json`` (git-ignored). The cache is refreshed when it is
older than ``MITRE_CACHE_TTL_DAYS`` (7 by default).

Resilience
----------
The platform must keep working without internet access, so the knowledge base
degrades in three levels, reported in ``status()["source"]``:

1. ``cache`` / ``live`` : official data (fresh cache, or just downloaded);
2. ``stale-cache``      : the refresh failed, the older cache is still used;
3. ``fallback``         : no data at all, the small built-in table of the
                          techniques the platform knows is used.

Configuration (environment variables or ``config/.env``)
--------------------------------------------------------
* ``MITRE_SOURCE_URL``       URL **or local path** of the Enterprise STIX bundle
* ``MITRE_CACHE_TTL_DAYS``   freshness of the cache (default 7)
* ``MITRE_AUTO_UPDATE``      ``false`` to never touch the network
"""

import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from config.settings import settings

logger = logging.getLogger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
)
DEFAULT_CACHE_PATH = os.path.join(REPO_ROOT, "data", "mitre", "techniques.json")

# Last-resort table (the techniques the platform used before it became dynamic),
# used only when neither the official data nor a cache is available.
FALLBACK_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1046": {"name": "Network Service Discovery", "tactics": ["discovery"]},
    "T1018": {"name": "Remote System Discovery", "tactics": ["discovery"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism",
              "tactics": ["privilege-escalation", "defense-evasion"]},
    "T1068": {"name": "Exploitation for Privilege Escalation",
              "tactics": ["privilege-escalation"]},
    "T1055": {"name": "Process Injection",
              "tactics": ["defense-evasion", "privilege-escalation"]},
    "T1547": {"name": "Boot or Logon Autostart Execution",
              "tactics": ["persistence", "privilege-escalation"]},
    "T1053": {"name": "Scheduled Task/Job",
              "tactics": ["execution", "persistence", "privilege-escalation"]},
    "T1543": {"name": "Create or Modify System Process",
              "tactics": ["persistence", "privilege-escalation"]},
    "T1570": {"name": "Lateral Tool Transfer", "tactics": ["lateral-movement"]},
    "T1021": {"name": "Remote Services", "tactics": ["lateral-movement"]},
    "T1078": {"name": "Valid Accounts",
              "tactics": ["defense-evasion", "persistence", "privilege-escalation",
                          "initial-access"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"]},
    "T1560": {"name": "Archive Collected Data", "tactics": ["collection"]},
    "T1005": {"name": "Data from Local System", "tactics": ["collection"]},
}

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_SPACES = re.compile(r"\s+")


def _clean_description(text: str, limit: int = 700) -> str:
    text = _CITATION.sub("", text or "")
    text = _MD_LINK.sub(r"\1", text)
    text = _SPACES.sub(" ", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "..."


def build_slim_cache(bundle: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Reduce a STIX bundle to the techniques the platform needs."""
    objects = bundle.get("objects", [])

    version = None
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            break

    techniques: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        reference = next(
            (
                r for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack" and r.get("external_id")
            ),
            None,
        )
        if not reference:
            continue

        technique_id = reference["external_id"]
        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[technique_id] = {
            "id": technique_id,
            "name": obj.get("name", technique_id),
            "summary": _clean_description(obj.get("description", "")),
            "tactics": tactics,
            "url": reference.get("url")
            or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent_id": technique_id.split(".")[0] if "." in technique_id else None,
        }

    return {
        "attack_version": version,
        "source": source,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "technique_count": len(techniques),
        "techniques": techniques,
    }


class MitreKnowledgeBase:
    """Thread-safe, lazily loaded ATT&CK technique catalogue."""

    def __init__(
        self,
        cache_path: Optional[str] = None,
        source_url: Optional[str] = None,
        ttl_days: Optional[float] = None,
        auto_update: Optional[bool] = None,
    ):
        self._cache_path = cache_path
        self._source_url = source_url
        self._ttl_days = ttl_days
        self._auto_update = auto_update

        self._lock = threading.RLock()
        self._data: Optional[Dict[str, Any]] = None
        self._level = "fallback"      # fallback | stale-cache | cache | live
        self._last_error: Optional[str] = None
        self._refreshing = False

    # ------------------------------------------------------------ settings
    @property
    def cache_path(self) -> str:
        return self._cache_path or getattr(settings, "mitre_cache_path", "") or DEFAULT_CACHE_PATH

    @property
    def source_url(self) -> str:
        return self._source_url or getattr(settings, "mitre_source_url", "") or DEFAULT_SOURCE_URL

    @property
    def ttl_seconds(self) -> float:
        days = self._ttl_days
        if days is None:
            days = getattr(settings, "mitre_cache_ttl_days", 7)
        return float(days) * 86400

    @property
    def auto_update(self) -> bool:
        if self._auto_update is not None:
            return self._auto_update
        return bool(getattr(settings, "mitre_auto_update", True))

    # --------------------------------------------------------------- cache
    def _cache_age(self) -> Optional[float]:
        try:
            return time.time() - os.path.getmtime(self.cache_path)
        except OSError:
            return None

    def _read_cache(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data.get("techniques"), dict) and data["techniques"]:
                return data
        except (OSError, ValueError):
            pass
        return None

    def _write_cache(self, data: Dict[str, Any]) -> None:
        directory = os.path.dirname(self.cache_path)
        os.makedirs(directory, exist_ok=True)
        # atomic write: a crash never leaves a half-written cache behind
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False)
            os.replace(tmp, self.cache_path)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    # ------------------------------------------------------------- loading
    def load_cache(self) -> bool:
        """Load the local cache if there is one. Fast (a few MB). Never uses the network."""
        with self._lock:
            data = self._read_cache()
            if data is None:
                return False
            age = self._cache_age()
            fresh = age is not None and age < self.ttl_seconds
            self._data = data
            self._level = "cache" if fresh else "stale-cache"
            return True

    def _download_bundle(self) -> Dict[str, Any]:
        source = self.source_url
        if os.path.exists(source):                      # local file (offline install, tests)
            with open(source, "r", encoding="utf-8") as handle:
                return json.load(handle)

        import requests

        response = requests.get(source, timeout=120)
        response.raise_for_status()
        return response.json()

    def refresh(self) -> bool:
        """Download the official bundle and rebuild the cache. Slow (tens of seconds)."""
        with self._lock:
            if self._refreshing:
                return False
            self._refreshing = True

        try:
            logger.info("Updating the MITRE ATT&CK knowledge base from %s", self.source_url)
            bundle = self._download_bundle()
            data = build_slim_cache(bundle, self.source_url)
            if not data["techniques"]:
                raise ValueError("the bundle contains no ATT&CK technique")

            self._write_cache(data)

            with self._lock:
                self._data = data
                self._level = "live"
                self._last_error = None
            logger.info(
                "MITRE ATT&CK %s loaded: %s techniques",
                data["attack_version"], data["technique_count"],
            )
            return True

        except Exception as exc:  # network, JSON, disk... must never crash the platform
            logger.warning("MITRE ATT&CK update failed: %s", exc)
            with self._lock:
                self._last_error = str(exc)
                if self._data is not None:
                    self._level = "stale-cache"
            return False

        finally:
            with self._lock:
                self._refreshing = False

    def ensure_fresh(self) -> None:
        """Startup routine: use the cache, refresh it when missing or stale."""
        have_cache = self.load_cache()
        age = self._cache_age()
        stale = (not have_cache) or age is None or age >= self.ttl_seconds

        if stale and self.auto_update:
            self.refresh()

    def ensure_loaded(self) -> None:
        """Cheap, non-blocking: make sure the local cache (if any) is in memory."""
        if self._data is None:
            self.load_cache()

    # ------------------------------------------------------------- queries
    @property
    def techniques(self) -> Dict[str, Dict[str, Any]]:
        """Technique catalogue: official data when available, else the built-in table."""
        self.ensure_loaded()
        with self._lock:
            if self._data is not None:
                return self._data["techniques"]
        return {
            tid: {
                "id": tid, "name": t["name"], "summary": "", "tactics": t["tactics"],
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                "platforms": [], "is_subtechnique": "." in tid,
                "parent_id": tid.split(".")[0] if "." in tid else None,
            }
            for tid, t in FALLBACK_TECHNIQUES.items()
        }

    @property
    def is_official(self) -> bool:
        self.ensure_loaded()
        return self._data is not None

    def get(self, technique_id: str) -> Optional[Dict[str, Any]]:
        return self.techniques.get(str(technique_id).strip().upper())

    def name(self, technique_id: str) -> str:
        technique = self.get(technique_id)
        return technique["name"] if technique else ""

    def source_label(self) -> str:
        """Short provenance string attached to every correlated technique."""
        self.ensure_loaded()
        with self._lock:
            if self._data is None:
                return "table de repli (hors ligne)"
            version = self._data.get("attack_version")
            label = f"MITRE ATT&CK v{version}" if version else "MITRE ATT&CK"
            return label if self._level in ("live", "cache") else f"{label} (cache périmé)"

    def status(self) -> Dict[str, Any]:
        self.ensure_loaded()
        with self._lock:
            data = self._data
            return {
                "source": self._level,
                "official_data": data is not None,
                "attack_version": data.get("attack_version") if data else None,
                "technique_count": len(self.techniques),
                "fetched_at": data.get("fetched_at") if data else None,
                "origin": data.get("source") if data else None,
                "cache_path": self.cache_path,
                "cache_ttl_days": self.ttl_seconds / 86400,
                "auto_update": self.auto_update,
                "refreshing": self._refreshing,
                "last_error": self._last_error,
            }


mitre_kb = MitreKnowledgeBase()
