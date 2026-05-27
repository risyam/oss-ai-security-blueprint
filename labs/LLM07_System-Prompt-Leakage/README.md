# LLM07 — System Prompt Leakage

> **OWASP Reference:** [LLM07](https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/)

## Real-World Scenario

A banking operations assistant has internal rules for transfer authorization. In the vulnerable version, sensitive internal instructions are embedded directly in the prompt, making extraction attacks practical. In the secured version, secrets and authorization are externalized and monitored.

## Quick Start

```bash
# Vulnerable
cd labs/LLM07_System-Prompt-Leakage/Vulnerable-Version
docker compose up --build

# Secured
cd labs/LLM07_System-Prompt-Leakage/Secured-Version
docker compose up --build
```

## Lab Ports

- Vulnerable: `http://localhost:8513`
- Secured: `http://localhost:8514`

## What This Lab Demonstrates

- Vulnerable path: prompt extraction reveals internal behavior and demo token metadata.
- Secured path: backend authorization and secret-broker pattern prevent prompt-only trust.

## Security Controls (`secure-lib`)

- `RuntimeSecretBroker`
- `PolicyEnforcer`
- `SystemPromptLeakDetector`
- `PromptExposureGuard`
- `PromptCanaryMonitor`

See `attack-script.md` in each version and `Secured-Version/control-mapping.md` for implementation mapping.
