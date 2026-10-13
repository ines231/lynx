from fastapi import APIRouter, BackgroundTasks, HTTPException
from typing import Optional

from ai_service.mitre.correlator import STAGE_TACTICS, mitre_correlator
from ai_service.mitre.knowledge_base import mitre_kb

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/status")
async def mitre_status():
    """State of the ATT&CK knowledge base: source, version, size, freshness."""
    return mitre_kb.status()


@router.post("/refresh")
async def mitre_refresh(background_tasks: BackgroundTasks):
    """Re-download the official ATT&CK data (runs in the background, tens of seconds)."""
    if mitre_kb.status()["refreshing"]:
        return {"status": "already_running"}

    background_tasks.add_task(mitre_kb.refresh)
    return {"status": "started", "check": "/api/mitre/status"}


@router.get("/techniques/{technique_id}")
async def get_technique(technique_id: str):
    technique = mitre_kb.get(technique_id)
    if technique is None:
        raise HTTPException(status_code=404, detail=f"Technique inconnue : {technique_id}")
    return technique


@router.get("/search")
async def search_techniques(q: str, stage: Optional[str] = None, limit: int = 5):
    """
    Search the catalogue the way the correlator does.

    `stage` (reconnaissance, exploitation, persistence, lateral_movement,
    exfiltration) restricts the result to the compatible ATT&CK tactics.
    """
    if stage is not None and stage not in STAGE_TACTICS:
        raise HTTPException(
            status_code=422,
            detail=f"stage doit valoir l'une de : {', '.join(STAGE_TACTICS)}",
        )

    event = {"event_type": q, "rule_description": q, "kill_chain_stage": stage or ""}
    probe = type(mitre_correlator)(mitre_kb, top_k=max(1, min(limit, 20)))

    if stage is None:
        results = []
        for candidate_stage in STAGE_TACTICS:
            results.extend(probe.match_event({**event, "kill_chain_stage": candidate_stage}))
        results.sort(key=lambda r: -r["score"])
        results = results[:limit]
    else:
        results = probe.match_event(event)

    return {"query": q, "stage": stage, "results": results, "knowledge_base": mitre_kb.source_label()}
