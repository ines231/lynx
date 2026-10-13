"""
Dynamic correlation of security events with MITRE ATT&CK techniques.

Instead of a hard-coded ``event_type -> technique`` table, each event is
matched against the whole ATT&CK catalogue (``MitreKnowledgeBase``):

1. **Explicit IDs.** If the source already provides ATT&CK ids (a real Wazuh
   rule carries ``rule.mitre.id``), they are used as they are.
2. **Retrieval.** Otherwise a query is built from what the event says (type,
   process, command line, rule description). Every technique is scored with a
   TF-IDF style measure: a word found in the technique *name* counts three
   times more than one found in its description, and rare words weigh more
   than common ones.
3. **Kill-chain consistency.** Only techniques whose ATT&CK tactic is
   compatible with the kill-chain stage of the event are candidates.

Every returned technique says why it matched (``matched_terms``), how strongly
(``score``) and where the knowledge comes from (``source``).
"""

import math
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ai_service.mitre.knowledge_base import MitreKnowledgeBase, mitre_kb

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
WORD = re.compile(r"[a-z0-9]+")

# Kill-chain stage of the platform -> ATT&CK tactics that can express it.
STAGE_TACTICS: Dict[str, Set[str]] = {
    "reconnaissance": {"reconnaissance", "discovery"},
    "exploitation": {"initial-access", "execution", "privilege-escalation"},
    "persistence": {"persistence"},
    "lateral_movement": {"lateral-movement"},
    "exfiltration": {"exfiltration", "collection"},
}

# Vocabulary of the platform's event types, expressed in ATT&CK wording.
# This only *helps the search* (query expansion): names, tactics, descriptions
# and links of the techniques themselves always come from the catalogue.
QUERY_HINTS: Dict[str, str] = {
    "port_scan": "network service discovery scan",
    "network_scan": "network service discovery scan",
    "dns_query": "remote system discovery",
    "privilege_escalation": "privilege escalation",
    "code_injection": "process injection",
    "service_installation": "create modify system process service",
    "service_install": "create modify system process service",
    "scheduled_task": "scheduled task job",
    "registry_modification": "boot logon autostart execution registry run keys",
    "lateral_movement": "remote services lateral tool transfer",
    "credential_use": "valid accounts",
    "data_transfer": "exfiltration over command and control channel",
    "archive_creation": "archive collected data",
    "file_access": "data from local system",
}

STOPWORDS = frozenset(
    """the and for with that this from are was were can may use used using into
    their they them its not has have been will which also such other when then
    than via per out any all more most some only both each over under between
    adversaries adversary attackers attacker system systems detected detection
    event events possible attempt unusual suspicious""".split()
)

NAME_WEIGHT = 3.0
SUMMARY_WEIGHT = 1.0
MIN_SCORE = 4.0


def _stem(word: str) -> str:
    for suffix in ("ations", "ation", "ings", "ing", "ies", "es", "ed", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def _tokens(text: str) -> List[str]:
    words = WORD.findall((text or "").lower())
    return [
        _stem(w) for w in words
        if len(w) >= 3 and w not in STOPWORDS and not w.isdigit()
    ]


class _Index:
    """Inverted statistics over the technique catalogue (rebuilt when it changes)."""

    def __init__(self, techniques: Dict[str, Dict[str, Any]]):
        self.techniques = techniques
        self.name_tokens: Dict[str, Set[str]] = {}
        self.summary_tokens: Dict[str, Set[str]] = {}
        document_frequency: Dict[str, int] = {}

        for tid, technique in techniques.items():
            name = set(_tokens(technique.get("name", "")))
            summary = set(_tokens(technique.get("summary", "")))
            self.name_tokens[tid] = name
            self.summary_tokens[tid] = summary
            for token in name | summary:
                document_frequency[token] = document_frequency.get(token, 0) + 1

        total = max(len(techniques), 1)
        self.idf = {
            token: math.log(1 + total / (1 + df))
            for token, df in document_frequency.items()
        }

    def score(self, technique_id: str, query: Iterable[str]) -> Tuple[float, List[str]]:
        name = self.name_tokens[technique_id]
        summary = self.summary_tokens[technique_id]
        total = 0.0
        matched: List[str] = []

        for token in set(query):
            idf = self.idf.get(token)
            if idf is None:
                continue
            if token in name:
                total += NAME_WEIGHT * idf
                matched.append(token)
            elif token in summary:
                total += SUMMARY_WEIGHT * idf
                matched.append(token)

        return total, sorted(matched)


class MitreCorrelator:
    """Maps the events of a correlated attack to ATT&CK techniques."""

    def __init__(self, kb: Optional[MitreKnowledgeBase] = None, top_k: int = 1):
        self.kb = kb or mitre_kb
        self.top_k = top_k
        self._index: Optional[_Index] = None
        self._index_key: Optional[int] = None

    # ------------------------------------------------------------- helpers
    def _get_index(self) -> _Index:
        techniques = self.kb.techniques
        key = id(techniques)
        if self._index is None or self._index_key != key:
            self._index = _Index(techniques)
            self._index_key = key
        return self._index

    @staticmethod
    def explicit_ids(event: Dict[str, Any]) -> List[str]:
        """ATT&CK ids already provided by the data source (e.g. Wazuh rule.mitre)."""
        found: List[str] = []
        sources = [event.get("mitre"), event.get("mitre_ids"), event.get("metadata")]
        rule = event.get("rule")
        if isinstance(rule, dict):
            sources.append(rule.get("mitre"))

        for source in sources:
            if source is None:
                continue
            for match in TECHNIQUE_ID.findall(str(source)):
                technique_id = match.upper()
                if technique_id not in found:
                    found.append(technique_id)
        return found

    @staticmethod
    def build_query(event: Dict[str, Any]) -> List[str]:
        event_type = str(event.get("event_type") or "")
        parts = [
            event_type.replace("_", " "),
            QUERY_HINTS.get(event_type, ""),
            str(event.get("process_name") or "").rsplit(".", 1)[0],
            str(event.get("command_line") or ""),
            str(event.get("rule_description") or ""),
        ]
        return _tokens(" ".join(parts))

    # ---------------------------------------------------------- public API
    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Best ATT&CK techniques for one event (``kill_chain_stage`` must be set)."""
        index = self._get_index()
        stage = event.get("kill_chain_stage", "unknown")
        allowed = STAGE_TACTICS.get(stage)
        results: List[Dict[str, Any]] = []

        # 1. ids given by the source
        for technique_id in self.explicit_ids(event):
            technique = index.techniques.get(technique_id)
            if technique:
                results.append(self._result(technique, 100.0, ["id fourni par la source"], "source"))

        if results:
            return results[: max(self.top_k, len(results))]

        # 2. retrieval, restricted to tactics compatible with the stage
        if not allowed:
            return []

        query = self.build_query(event)
        if not query:
            return []

        scored = []
        for technique_id, technique in index.techniques.items():
            if not (set(technique.get("tactics", [])) & allowed):
                continue
            score, matched = index.score(technique_id, query)
            if score >= MIN_SCORE:
                scored.append((score, technique_id, matched))

        # best score first; on a tie prefer the parent technique (more general)
        scored.sort(key=lambda s: (-s[0], "." in s[1], s[1]))

        for score, technique_id, matched in scored[: self.top_k]:
            results.append(self._result(index.techniques[technique_id], score, matched, "retrieval"))
        return results

    def map_attack(self, attack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Techniques for a whole attack, deduplicated, in order of first appearance."""
        merged: Dict[str, Dict[str, Any]] = {}

        for event in attack.get("events", []):
            for match in self.match_event(event):
                entry = merged.get(match["technique_id"])
                event_type = event.get("event_type", "")
                if entry is None:
                    entry = {
                        **match,
                        "stage": event.get("kill_chain_stage", "unknown"),
                        "event_type": event_type,
                        "event_types": [event_type],
                        "events_matched": 1,
                    }
                    merged[match["technique_id"]] = entry
                else:
                    entry["events_matched"] += 1
                    if event_type not in entry["event_types"]:
                        entry["event_types"].append(event_type)
                    entry["score"] = max(entry["score"], match["score"])

        return list(merged.values())

    def _result(self, technique, score, matched, method) -> Dict[str, Any]:
        return {
            "technique_id": technique["id"],
            "name": technique["name"],
            # ``description`` keeps the historical meaning (the technique name)
            "description": technique["name"],
            "summary": technique.get("summary", ""),
            "tactics": technique.get("tactics", []),
            "url": technique.get("url", ""),
            "score": round(float(score), 2),
            "matched_terms": matched,
            "method": method,
            "source": self.kb.source_label(),
        }


mitre_correlator = MitreCorrelator()
