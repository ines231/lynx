# Rapport de Projet de Fin d’Année — LYNX

## Plateforme probabiliste de Threat Hunting

**Étudiant :** [Nom Prénom]  
**Établissement :** [Établissement]  
**Formation :** [Formation]  
**Encadrant :** [Nom de l’encadrant]  
**Année universitaire :** 2025–2026  
**Date :** 7 octobre 2026

---

## Résumé

La multiplication des événements de sécurité et la sophistication des attaques rendent insuffisante une approche fondée uniquement sur des règles statiques et des niveaux de sévérité. Le projet LYNX propose une plateforme de Threat Hunting orientée probabilité et quantification du risque.

L’objectif est de transformer un événement de sécurité en une information exploitable par un analyste : comparaison avec un comportement normal, estimation d’une probabilité d’anomalie, enrichissement par Threat Intelligence, corrélation selon une chaîne d’attaque, estimation financière du risque et recommandation de traitement.

L’architecture développée repose principalement sur un service FastAPI en Python. Elle intègre des générateurs d’événements inspirés de Wazuh, un service d’enrichissement de Threat Intelligence, un détecteur d’anomalies basé notamment sur Isolation Forest, des modèles statistiques de probabilité d’anomalie, un moteur de risque inspiré de FAIR avec simulation de Monte Carlo, une corrélation Kill Chain, la génération de rapports d’investigation et une interface Web destinée à l’analyste.

Le dashboard finalisé constitue la couche de visualisation et d’exploitation de ces résultats. Il présente les indicateurs clés, les risques financiers, le flux des événements, la progression de la Kill Chain, la synthèse d’investigation, les IOCs, les techniques MITRE ATT&CK et les recommandations.

**Mots-clés :** Threat Hunting, cybersécurité, anomalie, Machine Learning, Isolation Forest, Threat Intelligence, Kill Chain, MITRE ATT&CK, FAIR, Monte Carlo, FastAPI.

---

# 1. Introduction

## 1.1 Contexte

Les systèmes d’information produisent aujourd’hui un volume important de journaux et d’événements de sécurité. Les solutions traditionnelles de supervision permettent de détecter certaines activités suspectes, mais une alerte isolée ne permet pas toujours de déterminer sa probabilité de caractère malveillant ni son impact métier.

Dans un Security Operations Center, l’analyste doit donc répondre à plusieurs questions : que s’est-il passé ? L’activité est-elle réellement inhabituelle ? Est-elle probablement malveillante ? S’inscrit-elle dans une attaque plus large ? Quel serait l’impact financier ? Quelle action faut-il prioriser ?

LYNX a été conçu pour apporter une réponse structurée à ces questions.

## 1.2 Problématique

Une approche classique peut être résumée par :

`événement → règle → score → sévérité`

LYNX cherche plutôt à suivre la chaîne :

`événement → baseline → probabilité d’anomalie → corrélation → risque → traitement`

Cette différence permet de passer d’une simple logique d’alerte à une logique d’aide à la décision.

## 1.3 Objectifs

Les objectifs principaux sont :

- construire une représentation du comportement normal ;
- identifier les événements qui s’en écartent ;
- utiliser des techniques statistiques et de Machine Learning pour la détection ;
- enrichir les événements avec des informations de Threat Intelligence ;
- corréler plusieurs événements selon une Kill Chain ;
- associer les événements à des techniques MITRE ATT&CK ;
- quantifier le risque à l’aide d’une approche inspirée de FAIR ;
- produire des recommandations de traitement ;
- fournir un dashboard permettant à l’analyste de comprendre rapidement la situation.

---

# 2. Étude et conception

## 2.1 Principe général

Le pipeline fonctionnel de LYNX est organisé comme suit :

`Sources de sécurité → Enrichissement → Analyse comportementale → Risque → Corrélation → Investigation → Dashboard`

Dans la version actuelle, les connecteurs Wazuh et IntelOwl sont représentés par des implémentations mock destinées au développement et à la démonstration. L’architecture permet néanmoins de remplacer ces composants par des connecteurs réels.

## 2.2 Architecture logicielle

Le projet est structuré autour de plusieurs modules :

- `ai_service/app` : application FastAPI et API REST ;
- `ai_service/connectors` : connecteurs et modèles d’événements ;
- `ai_service/enrichment` : enrichissement Threat Intelligence ;
- `ai_service/features` et `ai_service/ml/features` : extraction de caractéristiques ;
- `ai_service/ml/anomaly` : détection d’anomalies ;
- `ai_service/risk` : analyse probabiliste et quantification du risque ;
- `ai_service/correlation` : corrélation Kill Chain ;
- `ai_service/reports` : génération de rapports ;
- `ai_service/hypotheses` : génération d’hypothèses de chasse ;
- `dashboard` : interface Web destinée à l’analyste ;
- `tests` : organisation des tests unitaires et d’intégration.

## 2.3 Technologies

| Technologie | Rôle |
|---|---|
| Python | Langage principal du backend |
| FastAPI | API REST et serveur applicatif |
| Pydantic | Modélisation et validation des données |
| NumPy / Pandas | Calcul numérique et traitement de données |
| Scikit-learn | Machine Learning, notamment Isolation Forest |
| TensorFlow | Prévu pour les modèles temporels |
| SciPy | Calculs statistiques |
| Joblib | Sauvegarde des modèles ML |
| JavaScript / HTML / CSS | Dashboard |
| Ollama | Couche narrative optionnelle |
| Pytest | Tests |

---

# 3. Détection des anomalies

## 3.1 Baseline comportementale

Avant de décider qu’un événement est anormal, LYNX cherche à caractériser le comportement habituel. La baseline prend notamment en compte les habitudes temporelles, les processus utilisés et les caractéristiques réseau.

L’intérêt est de comparer une observation à un contexte de référence plutôt que de considérer qu’un événement est suspect uniquement parce qu’il correspond à une règle.

## 3.2 Probabilité d’anomalie

Le module `anomaly_probability` combine trois dimensions :

- anomalie temporelle ;
- anomalie liée au processus ;
- anomalie réseau.

La combinaison utilisée dans le projet donne :

`P(anomalie) = 0.30 P_t + 0.35 P_p + 0.35 P_n`

Cette valeur est comprise entre 0 et 1 et peut être présentée sous forme de pourcentage dans le dashboard.

## 3.3 Isolation Forest

Le projet contient également un détecteur Isolation Forest. L’algorithme apprend une représentation du comportement normal à partir de caractéristiques extraites des événements.

L’Isolation Forest est adaptée à la détection d’observations atypiques sans nécessiter un jeu de données entièrement étiqueté. Dans LYNX, elle complète l’analyse probabiliste et fournit une détection multivariée.

Le service expose notamment des opérations d’entraînement et de détection sur un événement ou un lot d’événements.

---

# 4. Threat Intelligence et enrichissement

## 4.1 Objectif

Un événement réseau ou système peut être difficile à interpréter sans contexte. L’enrichissement consiste à rechercher des informations supplémentaires sur les indicateurs présents dans l’événement.

LYNX prévoit notamment :

- réputation des adresses IP source ;
- réputation des adresses IP destination ;
- analyse des hash ;
- analyse des URL présentes dans certaines commandes.

## 4.2 Architecture extensible

Le service d’enrichissement repose sur une abstraction de fournisseur. La version de développement utilise un fournisseur mock, ce qui permet de tester le pipeline sans dépendre d’API externes.

Cette conception facilite l’intégration future de véritables sources de Threat Intelligence.

---

# 5. Corrélation de la Kill Chain

## 5.1 Motivation

Une suite d’événements isolés peut sembler peu significative. En revanche, plusieurs événements appartenant à différentes phases d’une attaque peuvent révéler une progression cohérente.

LYNX classe les événements selon cinq étapes :

1. Reconnaissance
2. Exploitation
3. Persistence
4. Lateral Movement
5. Exfiltration

Les événements sont ensuite regroupés notamment par adresse IP source et analysés chronologiquement.

## 5.2 Sévérité et confiance

La sévérité dépend de la progression observée. La présence d’une exfiltration entraîne par exemple une sévérité critique, tandis qu’un mouvement latéral conduit à une sévérité élevée.

Le moteur calcule également une confiance à partir du nombre d’événements corrélés et d’informations de Threat Intelligence disponibles.

---

# 6. Quantification du risque

## 6.1 Approche FAIR

L’objectif n’est plus seulement de dire qu’un événement est « critique », mais d’estimer son exposition potentielle.

Le moteur implémente plusieurs concepts inspirés de FAIR :

- Threat Event Frequency (TEF) ;
- Vulnerability ;
- Loss Event Frequency (LEF) ;
- Probable Loss Magnitude (PLM) ;
- Annual Loss Expectancy (ALE) ;
- Value at Risk à 95 % et 99 % ;
- Expected Shortfall.

La relation principale utilisée est :

`LEF = TEF × Vulnerability`

puis :

`ALE = LEF × PLM`

## 6.2 Simulation de Monte Carlo

Le moteur utilise une simulation Monte Carlo afin de produire une distribution des pertes annuelles.

Le nombre d’événements est modélisé avec une loi de Poisson et la magnitude des pertes avec une loi lognormale. Cette simulation permet d’extraire des indicateurs comme la VaR 95 % et la VaR 99 %.

Cette approche apporte une lecture plus riche qu’un score de sévérité unique.

## 6.3 Traitement du risque

Le module de traitement distingue plusieurs stratégies :

- remédiation ;
- mitigation ;
- acceptation ;
- transfert ou mécanismes compensatoires selon le contexte.

La recommandation dépend des métriques de risque calculées.

---

# 7. Investigation et MITRE ATT&CK

## 7.1 Génération du rapport

Lorsqu’une attaque est corrélée, LYNX peut produire un rapport structuré contenant :

- identifiant de l’attaque ;
- source ;
- sévérité ;
- confiance ;
- utilisateurs et hôtes affectés ;
- progression de la Kill Chain ;
- IOCs ;
- techniques MITRE ATT&CK ;
- chronologie ;
- recommandations ;
- prochaines étapes.

## 7.2 MITRE ATT&CK

Le projet possède un mapping entre plusieurs types d’événements et des techniques MITRE ATT&CK. Des exemples présents dans l’implémentation sont :

- T1046 — Network Service Discovery ;
- T1548 — Abuse Elevation Control Mechanism ;
- T1055 — Process Injection ;
- T1547 — Boot or Logon Autostart Execution ;
- T1053 — Scheduled Task/Job ;
- T1078 — Valid Accounts ;
- T1041 — Exfiltration Over C2 Channel ;
- T1560 — Archive Collected Data ;
- T1005 — Data from Local System.

Cette contextualisation aide l’analyste à relier les événements techniques à un référentiel reconnu.

---

# 8. Conception et intégration du dashboard

## 8.1 Objectif

Le dashboard constitue l’interface principale destinée à l’analyste. Il ne réalise pas lui-même les calculs de risque : il consomme les API du service FastAPI et transforme leurs résultats en informations visuelles.

Le service expose le dashboard sous `/dashboard` et une route d’accès directe `/dashboard-ui`.

## 8.2 Vue Overview

La page présente quatre indicateurs :

- événements analysés ;
- anomalies détectées ;
- attaques corrélées ;
- risque annuel estimé.

Cela donne immédiatement une vision synthétique de la situation.

## 8.3 Risk Intelligence

Cette zone affiche :

- la probabilité d’anomalie ;
- la VaR 95 % ;
- la VaR 99 % ;
- les événements les plus anormaux ;
- leur exposition financière ;
- leur priorité de traitement.

## 8.4 Event Risk Feed

Le tableau permet de comparer les événements selon :

- type d’événement ;
- utilisateur ;
- probabilité d’anomalie ;
- ALE ;
- priorité ;
- stratégie de traitement.

## 8.5 Kill Chain

Les cinq étapes sont représentées graphiquement. La version finalisée du dashboard met en évidence les étapes détectées à partir du rapport d’investigation.

## 8.6 Investigation Report Preview

Le dashboard affiche désormais une synthèse du rapport généré :

- Attack ID ;
- adresse IP source ;
- niveau de confiance ;
- nombre de techniques MITRE ;
- narration de l’attaque ;
- IOCs ;
- prochaines étapes.

Cette vue permet de passer rapidement de la détection à l’investigation.

---

# 9. API et intégration

Les principaux endpoints utilisés par l’interface sont :

- `GET /api/risk/analyze?normal_count=30` ;
- `GET /api/investigations/full-demo` ;
- `GET /api/anomalies/demo` ;
- les endpoints d’événements et d’enrichissement exposés par le service.

Le dashboard est servi directement par FastAPI grâce au montage des fichiers statiques :

`/dashboard → dashboard/`

Cette intégration évite d’avoir à déployer séparément l’interface et le backend pour le prototype.

---

# 10. Scénario de démonstration

Pour la soutenance, un scénario peut être présenté en suivant les étapes suivantes :

1. lancer le service FastAPI ;
2. ouvrir `/dashboard-ui` ;
3. présenter les KPI ;
4. expliquer la probabilité d’anomalie ;
5. montrer l’ALE et les VaR ;
6. suivre la progression de la Kill Chain ;
7. consulter le flux des événements ;
8. ouvrir la synthèse d’investigation ;
9. présenter les IOCs et techniques MITRE ;
10. terminer par la recommandation de traitement.

Le scénario de démonstration fourni par le projet génère un ensemble d’événements normaux pour établir une référence puis un scénario d’attaque destiné à tester la détection, la corrélation et la génération de rapport.

---

# 11. Résultats et limites

## 11.1 Résultats

Le projet aboutit à une chaîne fonctionnelle couvrant plusieurs niveaux :

`Événement → Enrichissement → Anomalie → Risque → Kill Chain → Rapport → Dashboard`

Le principal apport est la combinaison de détection comportementale, Machine Learning, Threat Intelligence, corrélation et quantification financière dans un même workflow.

## 11.2 Limites actuelles

La version actuelle reste un prototype académique et plusieurs améliorations sont nécessaires avant une utilisation en production :

- les connecteurs Wazuh et IntelOwl sont encore mock ;
- les données utilisées pour les démonstrations sont générées ;
- les paramètres financiers du modèle FAIR sont des estimations et doivent être calibrés avec des données métier réelles ;
- certaines API externes ne sont pas encore branchées ;
- la persistance des résultats doit être renforcée ;
- l’authentification et l’autorisation du dashboard doivent être ajoutées ;
- les tests automatisés doivent être étendus ;
- le monitoring et le déploiement industriel restent à compléter.

Ces limites ne remettent pas en cause l’architecture proposée ; elles définissent principalement les étapes nécessaires pour passer du prototype à une plateforme opérationnelle.

---

# 12. Perspectives

Les principales perspectives sont :

1. connecter LYNX à un véritable Wazuh/Elastic ;
2. intégrer des sources Threat Intelligence réelles ;
3. remplacer les données mock par des flux continus ;
4. entraîner les modèles sur des historiques réels ;
5. ajouter des modèles temporels LSTM ;
6. enrichir le mapping MITRE ;
7. ajouter une authentification analyste ;
8. stocker les investigations et leur historique ;
9. ajouter des filtres temporels et par hôte/utilisateur ;
10. permettre l’export PDF des investigations ;
11. déployer l’ensemble avec Docker ;
12. ajouter une chaîne CI/CD et des tests de non-régression.

---

# Conclusion

LYNX propose une approche de Threat Hunting qui dépasse la simple classification des alertes. Le système cherche à caractériser le comportement normal, quantifier l’anomalie, contextualiser les indicateurs, corréler les événements et traduire les résultats techniques en risque compréhensible.

L’intégration du dashboard complète cette chaîne en fournissant à l’analyste une vue synthétique et exploitable : indicateurs de sécurité, risque financier, événements prioritaires, Kill Chain, IOCs, techniques MITRE et recommandations.

Le projet constitue ainsi une base cohérente pour une plateforme de détection et d’aide à la décision orientée risque. Les travaux futurs pourront principalement porter sur l’intégration de sources réelles, la calibration des modèles, la persistance des données et le durcissement de la plateforme pour un contexte de production.

---

## Annexe A — Structure simplifiée du projet

```
lynx/
├── ai_service/
│   ├── app/
│   │   ├── api/
│   │   └── main.py
│   ├── connectors/
│   ├── enrichment/
│   ├── correlation/
│   ├── hypotheses/
│   ├── ml/
│   ├── reports/
│   └── risk/
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── config/
├── tests/
└── requirements.txt
```

## Annexe B — Formules principales

`P(anomalie) = 0.30P_t + 0.35P_p + 0.35P_n`

`LEF = TEF × Vulnerability`

`ALE = LEF × PLM`

La simulation Monte Carlo fournit ensuite une distribution des pertes permettant notamment d’estimer la VaR 95 %, la VaR 99 % et l’Expected Shortfall.
