import json
import os
import time

import pytest

from ai_service.correlation.kill_chain import kill_chain_correlator
from ai_service.mitre.correlator import MitreCorrelator
from ai_service.mitre.knowledge_base import (
    MitreKnowledgeBase,
    build_slim_cache,
)


def _pattern(tid, name, tactics, description, **extra):
    return {
        "type": "attack-pattern",
        "name": name,
        "description": description,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics
        ],
        "x_mitre_platforms": ["Windows"],
        **extra,
    }


def _bundle():
    filler = [
        _pattern(f"T9{i:03d}", f"Unrelated Technique {i}", ["impact"], f"Something about topic{i}.")
        for i in range(30)
    ]
    return {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "99.9"},
            _pattern("T1046", "Network Service Discovery", ["discovery"],
                     "Adversaries may attempt to get a listing of services running on remote "
                     "hosts, using a port scan. (Citation: Foo 2020) See [the docs](https://x.y)."),
            _pattern("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"],
                     "Adversaries may exploit software vulnerabilities to elevate privileges."),
            _pattern("T1053.005", "Scheduled Task", ["persistence", "execution"],
                     "Adversaries may abuse the Windows Task Scheduler to schedule a task.",
                     x_mitre_is_subtechnique=True),
            _pattern("T1570", "Lateral Tool Transfer", ["lateral-movement"],
                     "Adversaries may transfer tools between systems in a compromised environment."),
            _pattern("T1005", "Data from Local System", ["collection"],
                     "Adversaries may search local system sources to find files of interest."),
            _pattern("T1111", "Revoked Technique", ["discovery"], "port scan scan scan",
                     revoked=True),
            _pattern("T1112", "Deprecated Technique", ["discovery"], "port scan scan scan",
                     x_mitre_deprecated=True),
            {"type": "malware", "name": "not a technique"},
            *filler,
        ],
    }


@pytest.fixture
def bundle_file(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle()), encoding="utf-8")
    return str(path)


def _kb(tmp_path, bundle_file, **kw):
    return MitreKnowledgeBase(
        cache_path=str(tmp_path / "cache" / "techniques.json"),
        source_url=bundle_file,
        ttl_days=7,
        **kw,
    )


# ------------------------------------------------------------ parsing
def test_slim_cache_keeps_only_active_techniques_and_cleans_descriptions():
    data = build_slim_cache(_bundle(), "test")

    assert data["attack_version"] == "99.9"
    assert "T1111" not in data["techniques"]          # revoked
    assert "T1112" not in data["techniques"]          # deprecated
    assert data["technique_count"] == len(data["techniques"]) == 35

    t = data["techniques"]["T1046"]
    assert t["tactics"] == ["discovery"]
    assert "Citation" not in t["summary"] and "https://x.y" not in t["summary"]
    assert t["url"] == "https://attack.mitre.org/techniques/T1046"

    sub = data["techniques"]["T1053.005"]
    assert sub["is_subtechnique"] and sub["parent_id"] == "T1053"


# ------------------------------------------------------------ knowledge base
def test_refresh_builds_the_cache_and_a_new_instance_reloads_it(tmp_path, bundle_file):
    kb = _kb(tmp_path, bundle_file)
    assert kb.refresh() is True
    assert kb.status()["source"] == "live"
    assert kb.status()["attack_version"] == "99.9"
    assert os.path.exists(kb.cache_path)

    other = _kb(tmp_path, bundle_file)
    assert other.load_cache() is True
    assert other.status()["source"] == "cache"
    assert other.name("t1046") == "Network Service Discovery"   # case-insensitive
    assert other.source_label() == "MITRE ATT&CK v99.9"


def test_a_failed_refresh_keeps_the_stale_cache(tmp_path, bundle_file):
    kb = _kb(tmp_path, bundle_file)
    kb.refresh()

    # make the cache old, then break the source
    old = time.time() - 30 * 86400
    os.utime(kb.cache_path, (old, old))
    broken = MitreKnowledgeBase(
        cache_path=kb.cache_path, source_url=str(tmp_path / "missing.json"), ttl_days=7
    )
    broken.ensure_fresh()

    assert broken.status()["source"] == "stale-cache"
    assert broken.status()["last_error"]
    assert broken.get("T1046") is not None
    assert "périmé" in broken.source_label()


def test_without_any_data_the_builtin_table_is_used(tmp_path):
    kb = MitreKnowledgeBase(
        cache_path=str(tmp_path / "none.json"),
        source_url=str(tmp_path / "missing.json"),
        auto_update=False,
    )
    kb.ensure_fresh()

    assert kb.status()["source"] == "fallback"
    assert not kb.is_official
    assert kb.name("T1046") == "Network Service Discovery"
    assert "hors ligne" in kb.source_label()


def test_auto_update_false_never_downloads(tmp_path, bundle_file):
    kb = _kb(tmp_path, bundle_file, auto_update=False)
    kb.ensure_fresh()

    assert not os.path.exists(kb.cache_path)
    assert kb.status()["source"] == "fallback"


def test_a_corrupt_cache_is_ignored(tmp_path, bundle_file):
    kb = _kb(tmp_path, bundle_file)
    os.makedirs(os.path.dirname(kb.cache_path))
    with open(kb.cache_path, "w") as handle:
        handle.write("{not json")

    assert kb.load_cache() is False
    kb.ensure_fresh()                       # stale/missing -> refresh repairs it
    assert kb.status()["source"] == "live"


# ------------------------------------------------------------ correlation
def _correlator(tmp_path, bundle_file, top_k=1):
    kb = _kb(tmp_path, bundle_file)
    kb.refresh()
    return MitreCorrelator(kb, top_k=top_k)


@pytest.mark.parametrize(
    "event, expected",
    [
        ({"event_type": "port_scan", "kill_chain_stage": "reconnaissance"}, "T1046"),
        ({"event_type": "privilege_escalation", "kill_chain_stage": "exploitation"}, "T1068"),
        ({"event_type": "lateral_movement", "kill_chain_stage": "lateral_movement"}, "T1570"),
        ({"event_type": "file_access", "kill_chain_stage": "exfiltration"}, "T1005"),
        (
            {"event_type": "service_installation", "kill_chain_stage": "persistence",
             "rule_description": "Suspicious scheduled task created"},
            "T1053.005",
        ),
    ],
)
def test_events_are_matched_to_the_right_technique(tmp_path, bundle_file, event, expected):
    matches = _correlator(tmp_path, bundle_file).match_event(event)

    assert [m["technique_id"] for m in matches] == [expected]
    match = matches[0]
    assert match["name"] and match["url"].startswith("https://attack.mitre.org/")
    assert match["matched_terms"] and match["score"] > 0
    assert match["source"] == "MITRE ATT&CK v99.9"


def test_the_stage_restricts_the_candidate_tactics(tmp_path, bundle_file):
    c = _correlator(tmp_path, bundle_file)
    # "port scan" text, but the event is in the exfiltration stage: T1046 (discovery) is excluded
    ids = [m["technique_id"] for m in c.match_event(
        {"event_type": "port_scan", "kill_chain_stage": "exfiltration"})]
    assert "T1046" not in ids


def test_ids_given_by_the_source_win_over_retrieval(tmp_path, bundle_file):
    c = _correlator(tmp_path, bundle_file)
    event = {"event_type": "port_scan", "kill_chain_stage": "reconnaissance",
             "rule": {"mitre": {"id": ["T1570"]}}}

    matches = c.match_event(event)
    assert [m["technique_id"] for m in matches] == ["T1570"]
    assert matches[0]["method"] == "source"


def test_unknown_stage_or_empty_query_gives_nothing(tmp_path, bundle_file):
    c = _correlator(tmp_path, bundle_file)
    assert c.match_event({"event_type": "port_scan", "kill_chain_stage": "unknown"}) == []
    assert c.match_event({"kill_chain_stage": "reconnaissance"}) == []


def test_map_attack_deduplicates_and_keeps_the_event_types(tmp_path, bundle_file):
    c = _correlator(tmp_path, bundle_file)
    attack = {"events": [
        {"event_type": "port_scan", "kill_chain_stage": "reconnaissance"},
        {"event_type": "port_scan", "kill_chain_stage": "reconnaissance"},
        {"event_type": "lateral_movement", "kill_chain_stage": "lateral_movement"},
    ]}

    result = c.map_attack(attack)
    assert [t["technique_id"] for t in result] == ["T1046", "T1570"]
    assert result[0]["events_matched"] == 2
    assert result[0]["event_types"] == ["port_scan"]
    assert result[0]["stage"] == "reconnaissance"


# ------------------------------------------------------------ kill chain fix
@pytest.mark.parametrize(
    "event_type, stage",
    [
        ("port_scan", "reconnaissance"),
        ("privilege_escalation", "exploitation"),
        ("service_installation", "persistence"),
        ("lateral_movement", "lateral_movement"),
        # used to be classified as "persistence" because a keyword matched the dump
        ("file_access", "exfiltration"),
    ],
)
def test_declared_event_type_decides_the_kill_chain_stage(event_type, stage):
    event = {"event_type": event_type, "rule_description": "Suspicious scheduled task run",
             "process_name": "task.exe"}
    assert kill_chain_correlator.classify_stage(event) == stage
