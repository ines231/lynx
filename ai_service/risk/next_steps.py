"""
"What may come next?": hunting hypotheses derived from what has been observed.

For each kind of activity seen in the analysed window, the attack chain usually
continues in a few well-known ways (reconnaissance -> exploitation, stolen credentials ->
lateral movement, collection -> exfiltration, ...). This module lists those likely next
steps, with the ATT&CK techniques to look for and a concrete hint of what to search for in
the sensor logs.

These are expert-written hypotheses to guide the hunt, NOT predictions learned from data:
the confidence of each one only reflects how serious the observed events behind it are.
"""

from typing import Any, Dict, List

from ai_service.risk.common import fair_category

CATEGORY_LABELS = {
    "reconnaissance": "Reconnaissance",
    "exploitation": "Exploitation",
    "privilege_escalation": "Élévation de privilèges",
    "credential_access": "Vol d'identifiants",
    "persistence": "Persistance",
    "lateral_movement": "Mouvement latéral",
    "collection": "Collecte de données",
    "exfiltration": "Exfiltration",
    "defense_evasion": "Évasion / effacement de traces",
}

# observed category -> likely next steps: (next category, technique ids, why, what to search)
NEXT = {
    "reconnaissance": [
        ("exploitation", ["T1190", "T1133"],
         "Un scan sert à trouver un service attaquable.",
         "Tentatives d'exploitation ou connexions entrantes répétées vers les ports que le scan a trouvés ouverts."),
        ("credential_access", ["T1110"],
         "Les services d'authentification découverts sont souvent attaqués par force brute.",
         "Échecs d'authentification en série (SSH, RDP, web) depuis la même IP."),
    ],
    "exploitation": [
        ("persistence", ["T1053", "T1543"],
         "Après une première exécution, l'attaquant s'installe durablement.",
         "Nouvelles tâches cron / services systemd, fichiers modifiés dans les répertoires de démarrage."),
        ("privilege_escalation", ["T1068", "T1548"],
         "L'accès initial est rarement celui d'un administrateur.",
         "Utilisation inhabituelle de sudo ou de binaires setuid, exécutions sous un autre utilisateur."),
    ],
    "privilege_escalation": [
        ("credential_access", ["T1003", "T1555"],
         "Avec des droits élevés, l'attaquant récupère les identifiants du système.",
         "Lectures de /etc/shadow, de trousseaux de clés ou de la mémoire d'autres processus."),
        ("persistence", ["T1543", "T1053"],
         "Les droits élevés permettent d'installer une persistance difficile à retirer.",
         "Création de services, de comptes locaux ou de clés SSH autorisées."),
    ],
    "credential_access": [
        ("lateral_movement", ["T1021", "T1078"],
         "Les identifiants volés servent à se connecter à d'autres machines.",
         "Connexions SSH/RDP sortantes de cette machine vers d'autres hôtes internes, avec les comptes touchés."),
        ("privilege_escalation", ["T1548", "T1078"],
         "Des comptes privilégiés compromis donnent un accès plus large.",
         "Ouvertures de session administrateur inhabituelles (heure, origine)."),
    ],
    "persistence": [
        ("privilege_escalation", ["T1548", "T1068"],
         "Une persistance obtenue avec un compte limité mène souvent à la recherche de droits supérieurs.",
         "Modifications de sudoers, binaires setuid créés récemment."),
        ("lateral_movement", ["T1021"],
         "Un point d'appui durable sert de base pour atteindre le reste du réseau.",
         "Balayages et connexions vers les machines voisines depuis cet hôte."),
    ],
    "lateral_movement": [
        ("collection", ["T1005", "T1560"],
         "L'attaquant rassemble les données de la nouvelle machine.",
         "Accès en masse à des fichiers, création d'archives (tar, zip) dans /tmp ou le répertoire personnel."),
        ("exfiltration", ["T1041", "T1048"],
         "Les données collectées quittent ensuite le réseau.",
         "Gros transferts sortants vers des IP externes rares, connexions vers des services de partage."),
    ],
    "file_access": [
        ("exfiltration", ["T1041", "T1048"],
         "Des fichiers sensibles lus sont souvent envoyés à l'extérieur.",
         "Connexions sortantes juste après l'accès aux fichiers, vers une IP externe rare."),
        ("collection", ["T1560"],
         "Les fichiers lus sont souvent regroupés avant l'envoi.",
         "Création d'archives compressées juste après les accès."),
    ],
    "exfiltration": [
        ("defense_evasion", ["T1070"],
         "L'attaquant efface ses traces après avoir sorti les données.",
         "Suppression ou troncature de journaux, effacement de l'historique des commandes."),
    ],
    "process_execution": [
        ("persistence", ["T1053", "T1543"],
         "Une exécution de commandes est souvent suivie d'une installation durable.",
         "Nouvelles tâches planifiées ou services dans les minutes qui suivent."),
    ],
}

# raw event types that behave like another category for the purpose of the chain
ALIASES = {"scheduled_task": "persistence", "registry_modification": "persistence",
           "service_installation": "persistence", "code_injection": "exploitation",
           "data_transfer": "exfiltration", "archive_creation": "collection",
           "port_scan": "reconnaissance", "dns_query": "reconnaissance"}


def _observed_key(event_type: str, fair: str) -> str:
    for key in (event_type, fair, ALIASES.get(event_type)):
        if key in NEXT:
            return key
    return ""


def next_steps(events: List[Dict[str, Any]], risks: List[Dict[str, Any]],
               technique_name=None, limit: int = 6) -> List[Dict[str, Any]]:
    """Likely next steps, most relevant first.

    ``events`` and ``risks`` are aligned (same index). A step already observed in the
    window is not listed again. Relevance = hunting score of the strongest event that
    leads to the step.
    """
    seen = set()
    for event in events:
        event_type = str(event.get("event_type") or "").lower()
        seen.add(event_type)
        seen.add(fair_category(event))
        seen.add(ALIASES.get(event_type, event_type))

    found: Dict[str, Dict[str, Any]] = {}
    for event, risk in zip(events, risks):
        event_type = str(event.get("event_type") or "").lower()
        key = _observed_key(event_type, fair_category(event))
        if not key:
            continue
        score = float(risk.get("hunt_score") or 0.0)
        for nxt, ids, why, watch in NEXT[key]:
            if nxt in seen:
                continue
            item = found.setdefault(nxt, {
                "next": nxt,
                "label": CATEGORY_LABELS.get(nxt, nxt),
                "score": 0.0,
                "after": [],
                "techniques": [],
                "why": why,
                "watch": watch,
            })
            item["score"] = max(item["score"], score)
            if event_type not in item["after"]:
                item["after"].append(event_type)
            for tid in ids:
                if tid not in [t["id"] for t in item["techniques"]]:
                    item["techniques"].append({
                        "id": tid,
                        "name": (technique_name(tid) if technique_name else "") or "",
                    })

    ranked = sorted(found.values(), key=lambda x: -x["score"])[:limit]
    for item in ranked:
        item["score"] = round(item["score"], 1)
    return ranked
