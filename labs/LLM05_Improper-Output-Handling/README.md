# LLM05 — Improper Output Handling

> **OWASP:** [LLM05:2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

This lab demonstrates how unsafe handling of model output can become a direct exploit path.

## Labs

| Version | Port | Description |
|---------|------|-------------|
| [Vulnerable](./Vulnerable-Version/) | 8503 | Renders model HTML unsafely and triggers network actions from model output |
| [Secured](./Secured-Version/) | 8504 | Validates output, enforces schema, and gates side effects with policy + approval |

## Quick Start

```bash
# Vulnerable version
cd labs/LLM05_Improper-Output-Handling/Vulnerable-Version
docker compose up --build
```

```bash
# Secured version
cd labs/LLM05_Improper-Output-Handling/Secured-Version
docker compose up --build
```

Open:
- Vulnerable: `http://localhost:8503`
- Secured: `http://localhost:8504`
