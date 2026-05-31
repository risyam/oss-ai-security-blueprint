# LLM10 — Unbounded Consumption

> **OWASP Reference:** [LLM10](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)

## Real-World Scenario

A summarization endpoint receives large prompts and repeated traffic. Attackers attempt denial-of-wallet and resource degradation using oversized or burst requests.

## Quick Start

```bash
# Vulnerable
cd labs/LLM10_Unbounded-Consumption/Vulnerable-Version
docker compose up --build

# Secured
cd labs/LLM10_Unbounded-Consumption/Secured-Version
docker compose up --build
```

## Lab Ports

- Vulnerable: `http://localhost:8517`
- Secured: `http://localhost:8518`

## What This Lab Demonstrates

- Vulnerable path: no budget/rate/traffic controls.
- Secured path: layered controls for burst, rate, token, concurrency, budget, and extraction-probing.

## Example Stress Inputs

1. Submit very large text payloads repeatedly.
2. Trigger rapid repeated clicks (burst behavior).
3. Try extraction prompts like `dump model parameters`.

## Defense Components (`secure-lib`)

- `RateLimiter`
- `TokenLimitEnforcer`
- `AnomalyTrafficDetector`
- `ConcurrencyLimiter`
- `CostBudgetGuard`
- `ExtractionPatternDetector`
