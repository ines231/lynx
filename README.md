# LYNX : Probabilistic Threat Hunting Platform

Plateforme de *threat hunting* qui raisonne en **probabilités et en risque financier** plutôt qu'avec de simples étiquettes « faible / moyen / élevé ».

Pour chaque événement de sécurité, LYNX estime :

- à quel point il s'écarte du comportement normal (baseline) ;
- quelle perte annuelle il peut représenter (modèle FAIR, simulation de Monte Carlo) ;
- quel traitement appliquer (remédier, atténuer, transférer, accepter) ;
- à quelle étape de la *kill chain* il appartient et quelles techniques MITRE ATT&CK il mobilise.

```
événement -> comparaison à la baseline -> probabilité d'anomalie -> perte annuelle (ALE, VaR) -> traitement
```

> **État du projet.** Les données d'entrée viennent de **connecteurs simulés** (Wazuh et IntelOwl factices). Les chiffres illustrent la méthode ; ils ne décrivent pas une organisation réelle. Voir [Limites](#limites-et-état-réel).

## Sommaire

1. [Architecture](#architecture)
2. [Installation et lancement](#installation-et-lancement)
3. [API](#api)
4. [Méthode](#méthode)
5. [Résultats](#résultats)
6. [Rapport PDF](#rapport-pdf)
7. [Tests](#tests)
8. [Limites et état réel](#limites-et-état-réel)

## Architecture

```
ai_service/
  app/
    main.py                 application FastAPI + dashboard statique
    api/                    routes : events, anomalies, investigations, risk
  connectors/
    wazuh/mock_wazuh.py     générateur d'événements et de scénario d'attaque (simulé)
    intelowl/               enrichissement threat intel (simulé)
    models/event.py         modèles Pydantic des événements
  enrichment/               enrichissement des IP, domaines et hashes
  ml/
    baselines/              construction de la baseline utilisateur
    features/               extraction de caractéristiques
    anomaly/                Isolation Forest (détection binaire)
  risk/
    pipeline.py             pipeline complet, partagé par l'API et le PDF
    baseline_model.py       profil de comportement normal
    anomaly_probability.py  probabilité d'anomalie continue par événement
    chi_square_tests.py     test du chi-carré (événements, processus, ports, sévérités)
    monte_carlo_fair.py     quantification FAIR : ALE, VaR 95 % / 99 %
    risk_treatment.py       stratégie, priorité, contrôles recommandés
  correlation/kill_chain.py corrélation des événements sur la kill chain
  mitre/                    base ATT&CK officielle (cache local) et corrélation événement -> technique
  hypotheses/               hypothèses de chasse et requêtes suggérées
  reports/
    investigation_report.py rapport d'investigation (IOC, MITRE dynamique, chronologie)
    pdf_report.py           rapport PDF structuré
dashboard/                  interface web (HTML, CSS, JavaScript) et logo (assets/)
config/settings.py          paramètres (variables d'environnement ou config/.env)
tests/                      tests unitaires et d'intégration
```

## Installation et lancement

Prérequis : Python 3.12 (version utilisée sur la VM de développement).

```bash
git clone https://github.com/ines231/lynx.git
cd lynx
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Lancer l'API depuis la racine du dépôt :

```bash
uvicorn ai_service.app.main:app --reload --host 0.0.0.0 --port 8000
```

| Adresse | Contenu |
| --- | --- |
| `http://localhost:8000/dashboard-ui` | dashboard analyste |
| `http://localhost:8000/docs` | documentation interactive de l'API (Swagger) |
| `http://localhost:8000/health` | état du service |

Les paramètres (port, seuils, clés d'API de threat intelligence) se règlent par variables d'environnement ou dans un fichier `config/.env` à créer (optionnel, ignoré par git). Les valeurs par défaut sont dans `config/settings.py`.

## API

| Méthode | Route | Rôle |
| --- | --- | --- |
| GET | `/api/risk/analyze` | analyse complète ; renvoie un `analysis_id`. Paramètres : `normal_count` (5 à 500), `seed` (résultats reproductibles), `currency` (`TND` ou `USD`, remplace la devise configurée) |
| GET | `/api/risk/report.pdf` | rapport PDF. `analysis_id` : PDF de l'analyse affichée (410 si expirée) ; sans identifiant : nouvelle analyse |
| GET | `/api/mitre/status` | état de la base MITRE ATT&CK : source, version, nombre de techniques, fraîcheur |
| POST | `/api/mitre/refresh` | relance le téléchargement des données ATT&CK en arrière-plan |
| GET | `/api/mitre/search`, `/techniques/{id}` | recherche (`q`, `stage`) et fiche d'une technique |
| GET | `/api/risk/demo` | démonstration du moteur de risque de bout en bout |
| GET | `/api/events/sample`, `/attack-scenario` | événements simulés |
| POST | `/api/events/enrich`, `/enrich-batch`, `/ingest` | enrichissement et ingestion |
| GET / POST | `/api/anomalies/status`, `/train`, `/detect`, `/detect-batch`, `/demo` | détection par Isolation Forest |
| GET / POST | `/api/investigations/full-demo`, `/analyze-events` | corrélation, rapports et hypothèses |

Exemple reproductible :

```bash
curl "http://localhost:8000/api/risk/analyze?seed=7"
curl -o rapport.pdf "http://localhost:8000/api/risk/report.pdf?seed=7"
```

## Méthode

**Baseline.** Un profil de comportement normal est construit sur des événements de référence (heures, processus, ports, types d'événements, sévérités). La baseline ne contient que des types d'événements normaux (connexions, exécutions de processus, accès fichiers, connexions réseau, requêtes DNS), sinon les attaques « normaliseraient » la référence.

**Probabilité d'anomalie.** Chaque événement reçoit une probabilité continue qui combine l'écart temporel, l'écart de processus, l'écart réseau et la rareté de son type. Elle sert à hiérarchiser les événements. La décision binaire « anomalie ou non » reste celle de l'Isolation Forest.

**Test du chi-carré.** Il compare la distribution des types d'événements de la fenêtre d'attaque à celle de la baseline.

- H0 : la fenêtre provient de la distribution de la baseline. Seuil de décision : α = 0,05.
- Les effectifs de la baseline sont lissés (Lidstone) : un type jamais vu garde une probabilité faible mais non nulle.
- Statistique de Pearson `X² = Σ (O − E)² / E` sur l'union des catégories, avec `ddl = K − 1`.
- Si tous les effectifs attendus sont ≥ 5, la p-value suit la loi du chi-carré (méthode *asymptotique*). Sinon elle est estimée par un **test multinomial exact par simulation de Monte-Carlo** (10 000 tirages), valable sur les petites fenêtres typiques d'un SOC. La plus petite p-value possible vaut alors 1/10 001, affichée « < 0,0001 ».
- Le score `1 − p` mesure la **force de la preuve contre H0**. Ce n'est pas une probabilité calibrée d'attaque.
- Une version antérieure renvoyait la p-value brute quand le test n'était pas significatif, ce qui inversait le sens du score ; c'est corrigé.

**Quantification FAIR.** La fréquence d'événement de menace et la vulnérabilité donnent la fréquence d'événement de perte. Elle est combinée à l'amplitude de perte probable dans une simulation de Monte Carlo, ce qui donne la **perte annuelle attendue (ALE)**, la **valeur à risque** à 95 % et 99 %, et l'*expected shortfall*.

**Traitement du risque.** Selon l'ALE et le contexte, le moteur propose une stratégie (remédiation urgente, atténuation, transfert, acceptation, surveillance), une priorité, un délai et des contrôles.

**Kill chain.** Les événements sont classés par étape (reconnaissance, exploitation, persistence, mouvement latéral, exfiltration) d'après leur type, puis chaînés par continuité de source et de destination.

**Corrélation MITRE ATT&CK dynamique.** Aucun tableau n'est écrit en dur : les techniques viennent des données officielles de MITRE (STIX, sans clé d'API).

- Le catalogue Enterprise (≈ 700 techniques et sous-techniques actives) est téléchargé depuis `mitre-attack/attack-stix-data`, réduit à un cache local de moins de 1 Mo (`data/mitre/techniques.json`, ignoré par git) et rafraîchi tous les 7 jours. Le chargement se fait en arrière-plan au démarrage.
- Pour chaque événement, une requête est construite (type, processus, ligne de commande, description de la règle) et comparée à tout le catalogue avec un score de type TF-IDF : un mot trouvé dans le **nom** de la technique compte trois fois plus que dans sa description, et un mot rare pèse plus qu'un mot courant.
- Seules les techniques dont la **tactique ATT&CK est compatible avec l'étape de kill chain** de l'événement sont candidates.
- Si la source fournit déjà des identifiants ATT&CK (règle Wazuh réelle), ils sont utilisés tels quels.
- Chaque technique renvoyée indique son score, les termes qui ont déclenché la correspondance et sa provenance (version d'ATT&CK).
- **Hors ligne** : le cache périmé est conservé ; sans aucun cache, une petite table intégrée prend le relais.

```bash
python -m ai_service.mitre        # télécharger / rafraîchir la base maintenant
```

Configuration : `MITRE_SOURCE_URL` (URL ou chemin local d'un fichier STIX, utile sans accès internet), `MITRE_CACHE_TTL_DAYS` (7), `MITRE_AUTO_UPDATE` (`false` pour ne jamais utiliser le réseau).

## Résultats

Analyse reproductible : `GET /api/risk/analyze?seed=7` (baseline de 30 événements normaux, scénario d'attaque de 7 événements).

**Test du chi-carré sur le scénario**

| Indicateur | Valeur |
| --- | --- |
| Statistique X² | 112,18 |
| Degrés de liberté | 8 |
| p-value | < 0,0001 (1/10 001 au minimum) |
| Méthode | Monte-Carlo (effectif attendu minimum 0,10 < 5) |
| Taille d'effet (w de Cohen) | 4,00 |
| Décision | H0 rejetée : écart significatif avec la baseline |

Les types `port_scan`, `privilege_escalation`, `service_installation` et `lateral_movement` n'existent pas dans la baseline : ce sont eux qui font rejeter H0.

**Risque par événement** (montants en dinars tunisiens, 1 USD = 2,9927 DT)

| # | Événement | Utilisateur | Anomalie | ALE | VaR 95 % | VaR 99 % | Priorité |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | port_scan | n/a | 45,2 % | 434 DT | 24 469 DT | 31 473 DT | INFO |
| 2 | port_scan | n/a | 45,2 % | 434 DT | 24 469 DT | 31 473 DT | INFO |
| 3 | port_scan | n/a | 45,2 % | 775 DT | 24 825 DT | 36 430 DT | INFO |
| 4 | privilege_escalation | user1 | 35,2 % | 6 384 DT | 158 296 DT | 214 631 DT | INFO |
| 5 | service_installation | admin | 37,7 % | 1 847 DT | 101 056 DT | 125 350 DT | INFO |
| 6 | lateral_movement | admin | 57,7 % | 13 554 DT | 156 567 DT | 207 287 DT | INFO |
| 7 | file_access | service_account | 32,6 % | 17 497 DT | 736 409 DT | 1 093 973 DT | **CRITICAL** |

L'événement le plus exposé est l'accès à un fichier sensible (`C:\Data\Financial\reports.xlsx`) par un compte de service : **remédiation urgente, délai inférieur à 4 heures**, avec pour objectif une ALE ramenée de 17 497 DT à 2 625 DT (−85 %).

**Corrélation.** Une attaque reconstituée (gravité *critical*, confiance 78,6 %, source 192.168.1.50), **5 étapes sur 5** de la kill chain observées, 10 hypothèses de chasse et 5 techniques MITRE trouvées dynamiquement dans ATT&CK v19.2 :

| Étape | Événement | Technique ATT&CK |
| --- | --- | --- |
| Reconnaissance | port_scan | T1046 Network Service Discovery |
| Exploitation | privilege_escalation | T1068 Exploitation for Privilege Escalation |
| Persistence | service_installation | T1053.005 Scheduled Task |
| Mouvement latéral | lateral_movement | T1570 Lateral Tool Transfer |
| Exfiltration | file_access | T1537 Transfer Data to Cloud Account |

La technique de persistence vient de la description de l'événement (« Suspicious scheduled task created ») ; la correspondance est une aide à l'investigation, à valider par un analyste.

## Dashboard interactif

Le dashboard (`/dashboard-ui`) ne se contente pas d'afficher des chiffres :

| Élément | Rôle |
|---|---|
| Distribution des pertes | histogramme Monte-Carlo FAIR de l'événement le plus exposé, avec ALE, VaR 95 % et VaR 99 % |
| Observé vs baseline | comptes attendus et observés par type d'événement, et part de chacun dans la statistique du χ² |
| Kill chain cliquable | un clic sur une étape liste ses événements |
| Répartition des priorités | donut du nombre d'événements par priorité |
| Matrice MITRE ATT&CK | 14 tactiques en colonnes, techniques détectées en surbrillance (lien vers la fiche officielle) |
| Flux d'événements | recherche, filtres (priorité, étape), tri (anomalie, ALE, priorité) et panneau de détail au clic |
| Paramètres | taille de la baseline, seed, devise DT / $, actualisation automatique (30 ou 60 s), export CSV des événements affichés, thème clair / sombre |

Les graphiques sont des SVG écrits à la main (`dashboard/charts.js`) : aucune bibliothèque externe, le dashboard fonctionne hors ligne.

## Devise

Le moteur FAIR valorise les pertes en dollars américains (ses valeurs par défaut sont en USD). Tous les montants affichés (API, dashboard, PDF) sont convertis **une seule fois, à la sortie du pipeline**, en **dinars tunisiens (DT)** par défaut. Le taux est configurable :

```bash
DISPLAY_CURRENCY=TND        # ou USD pour garder les dollars
USD_TO_TND_RATE=2.9927      # dinars pour 1 dollar (12/10/2026) : à aligner sur le taux de la BCT
```

La réponse de `/api/risk/analyze` contient la devise utilisée (`currency`). Le taux est fixe : il n'est pas actualisé automatiquement.

## Rapport PDF

Le bouton **« Rapport PDF »** du dashboard télécharge le rapport de l'analyse affichée (même `analysis_id`, donc mêmes chiffres). Il contient :

1. synthèse exécutive ;
2. méthodologie ;
3. test du chi-carré (statistique, p-value, méthode, distribution observée et baseline) ;
4. risque par événement, avec graphiques ;
5. plan de traitement ;
6. kill chain ;
7. investigation (IOC, MITRE ATT&CK, chronologie) ;
8. hypothèses de chasse ;
9. recommandations et prochaines étapes ;
10. limites et lecture critique.

Une analyse reste en mémoire tant que le serveur tourne (32 analyses au maximum). Après un redémarrage, le bouton demande d'actualiser le dashboard.

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

Une soixantaine de tests unitaires (baseline, chi-carré, probabilités d'anomalie, FAIR, traitement du risque, pipeline, PDF, devise, MITRE, kill chain) et des tests d'intégration de l'API. Les tests MITRE n'utilisent pas le réseau : ils travaillent sur un mini-catalogue synthétique. Les tests du chi-carré vérifient notamment qu'une fenêtre normale obtient un score faible, qu'une fenêtre d'attaque avec des types inconnus est significative, que le score croît avec l'écart à la baseline, que la méthode asymptotique coïncide avec `scipy` et que le résultat est déterministe.

## Limites et état réel

- **Données simulées.** Wazuh et IntelOwl sont remplacés par des générateurs (`mock_wazuh`, `mock_intelowl`). Aucun flux de production n'est branché.
- **Échantillon réduit.** La baseline compte 30 événements et la fenêtre testée 7 : la puissance statistique est limitée, d'où la p-value estimée par simulation.
- **Correspondance MITRE automatique.** Elle repose sur une recherche textuelle dans le catalogue, pas sur une analyse sémantique : une description d'événement pauvre donne une correspondance approximative (par exemple T1537 pour un transfert de données vers une IP externe, alors que T1048 serait aussi défendable).
- **Taux de change fixe.** La conversion USD → DT utilise un taux configuré à la main, pas un cours en direct.
- **Paramètres FAIR non calibrés.** Fréquences, vulnérabilité et amplitude de perte sont des valeurs par défaut. L'ALE et la VaR donnent un ordre de grandeur pour prioriser, pas un budget.
- **Seuils de priorité.** La priorité dépend de seuils sur l'ALE : dans l'exemple ci-dessus, l'escalade de privilèges et le mouvement latéral restent classés « INFO / acceptation » alors qu'ils appartiennent à une attaque en cours. À corriger en tenant compte de l'étape de la kill chain.
- **Pas de LSTM ni de couche Ollama.** Ces pistes figuraient dans la première version du projet : le dossier `ai_service/llm/` est vide et `tensorflow` et `ollama` sont listés dans `requirements.txt` sans être utilisés par le code. L'analyse repose sur la baseline statistique, le chi-carré, l'Isolation Forest et FAIR.
- **Code dupliqué.** `ai_service/anomaly/` et `ai_service/features/` doublonnent `ai_service/ml/` et ne sont importés nulle part.
- **Avertissements.** Des appels à `datetime.utcnow()` (obsolète depuis Python 3.12) génèrent des `DeprecationWarning` sans conséquence fonctionnelle.

## Pistes d'évolution

- brancher un vrai flux Wazuh et un vrai fournisseur de threat intelligence ;
- calibrer les paramètres FAIR sur le contexte métier de l'organisation ;
- tenir compte de l'étape de la kill chain dans la priorité ;
- historiser les analyses dans une base de données plutôt qu'en mémoire ;
- ajouter un modèle temporel (LSTM) et une couche de narration par LLM, une fois les bases ci-dessus stabilisées.
