# Probabilistic Threat Hunting Platform

This project is a threat hunting platform focused on risk probability, not simple alert labels.

Instead of only showing low, medium, or high, the goal is to estimate:

- how unusual an event is compared to normal behavior
- how likely it is to be malicious
- what business risk it may create
- whether the risk should be remediated, accepted, transferred, or handled with compensating controls

The platform combines statistical analysis, machine learning, threat intelligence, kill chain correlation, and FAIR-style risk thinking.

## Main Idea

Traditional SOC tools often work like this:

```
event -> rule -> score -> severity badge
```

This platform is designed to work more like this:

```
event -> baseline comparison -> anomaly probability -> risk estimate -> treatment recommendation
```

Example:

- **Anomaly probability:** 68%
- **Estimated annual loss exposure:** $22,650
- **Recommended action:** remediate within 48 hours

## What It Does

- Builds behavioral baselines for users, systems, processes, ports, and activity time.
- Detects unusual activity using statistics and ML models.
- Uses probabilities instead of fixed rule-only scoring.
- Correlates events across attack stages such as reconnaissance, persistence, lateral movement, and exfiltration.
- Enriches IPs, domains, and hashes with threat intelligence.
- Estimates risk using FAIR-style concepts and Monte Carlo simulation.
- Produces investigation summaries, IOCs, MITRE ATT&CK context, and recommended actions.

## Core Structure

```
services/
  ai_service/
    app/
      enrichment/     threat intelligence
      features/       event feature extraction
      models/         anomaly detection
      correlation/    kill chain logic
      reports/        investigation reports
      llm/            optional Ollama narrative layer
```

Ollama is **not** the detection engine. It is only used at the end to help write investigation narratives from structured evidence.

## Risk Engine Direction

The risk engine is being designed around:

- normal distribution and z-score analysis
- chi-square tests for behavior changes
- Isolation Forest for multivariable anomaly detection
- LSTM models for temporal behavior
- Monte Carlo simulation for FAIR-style risk quantification

The intended result is a quantified risk view, not a vague severity label.

## Dashboard Goal

The dashboard should help an analyst quickly answer:

- What happened?
- How abnormal is it?
- What is the probability of malicious behavior?
- Which attack stages are involved?
- What is the estimated business risk?
- What should we do next?

Planned views:

- anomaly probability feed
- kill chain timeline
- threat intelligence lookup
- risk simulation panel
- investigation report preview
- treatment recommendation view

## Current Status

The project is in active development.

Current focus:

- AI service foundation
- probabilistic risk engine
- threat intelligence interfaces
- kill chain correlation
- dashboard visualization

**Next major step:** build the dashboard around probability, FAIR-style risk, and investigation workflow.
