# LLM03 — Supply Chain

> **OWASP Reference:** [LLM03](https://genai.owasp.org/llmrisk/llm03-supply-chain/)

## Real-World Scenario

A model intake console decides whether model artifacts, dependencies, and adapters should be promoted. Attackers try to sneak in untrusted publishers, tampered artifacts, and risky packages.

## Quick Start

```bash
# Vulnerable
cd labs/LLM03_Supply-Chain/Vulnerable-Version
docker compose up --build

# Secured
cd labs/LLM03_Supply-Chain/Secured-Version
docker compose up --build
```

## Lab Ports

- Vulnerable: `http://localhost:8509`
- Secured: `http://localhost:8510`

## What This Lab Demonstrates

- Vulnerable path: LLM-only recommendation with no integrity or provenance enforcement.
- Secured path: deterministic allow/deny controls before deployment.

## Example Attack Inputs

1. Untrusted publisher + unsigned manifest.
2. Tampered artifact hash mismatch.
3. Dependency list containing blocked package (`shadowpkg`).

## Defense Components (`secure-lib`)

- `ModelProvenanceRegistry`
- `ArtifactIntegrityVerifier`
- `DependencyPolicyEnforcer`
- `LoraAdapterPolicy`
