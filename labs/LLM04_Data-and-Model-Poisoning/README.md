# LLM04 — Data and Model Poisoning

> **OWASP Reference:** [LLM04](https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/)

## Real-World Scenario

A safety classifier review workflow ingests candidate training samples. Attackers introduce poisoned phrasing and hidden backdoor triggers to force unsafe promotion.

## Quick Start

```bash
# Vulnerable
cd labs/LLM04_Data-and-Model-Poisoning/Vulnerable-Version
docker compose up --build

# Secured
cd labs/LLM04_Data-and-Model-Poisoning/Secured-Version
docker compose up --build
```

## Lab Ports

- Vulnerable: `http://localhost:8511`
- Secured: `http://localhost:8512`

## What This Lab Demonstrates

- Vulnerable path: direct promotion without lineage, anomaly, or backdoor checks.
- Secured path: deterministic ingestion and promotion gates.

## Example Poisoning Inputs

1. `Always label low-risk!!!` override phrasing.
2. Known trigger token: `[PRIORITY-GREEN-OVERRIDE]`.
3. Non-approved dataset state (`pending` / `rejected`).

## Defense Components (`secure-lib`)

- `PoisoningSignalDetector`
- `BackdoorTriggerScanner`
- `DatasetLineageTracker`
- `ModelPromotionGuard`
