# OSS AI Security Blueprint

A practical, open-source blueprint for securing LLM-powered applications, focused on real attack paths and defensive controls. The repo includes architecture diagrams, threat mapping, and a runnable lab demonstrating RAG data poisoning (OWASP LLM08) in vulnerable vs secured implementations.

## What This Repo Contains

- `docs/` architecture diagrams and attack path mapping
- `labs/LLM08_Data-Poisoning/` runnable lab (vulnerable + secured)
- `secure-lib/` reusable LLM security components (scanners, validators, policy, monitoring)
- `controls/`, `governance/`, `compliance/`, `implementation/` placeholders for future expansion

## Quick Start

```bash
cd labs/LLM08_Data-Poisoning/Vulnerable-Version
docker compose up --build
```

```bash
cd labs/LLM08_Data-Poisoning/Secured-Version
docker compose up --build
```

## Current Focus

- OWASP LLM08 (Vector & Embedding Weaknesses)
- Prompt injection defenses
- Output validation
- Token and rate controls
- Document provenance validation

## Status

This repository is under active development. Expect ongoing expansion into agentic workflows, tool security, and policy enforcement.
