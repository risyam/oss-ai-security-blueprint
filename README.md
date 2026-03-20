# OSS AI Security Blueprint

A practical, open-source blueprint for securing LLM-powered applications, focused on real attack paths and defensive controls. The repo includes architecture diagrams, threat mapping, and runnable labs demonstrating OWASP LLM vulnerabilities in vulnerable vs secured implementations.

## What This Repo Contains

- `docs/` architecture diagrams and attack path mapping
- `labs/` runnable labs (vulnerable + secured):
  - `LLM01_Prompt-Injection/` (Direct/Indirect Prompt Injection)
  - `LLM05_Improper-Output-Handling/` (Unsafe HTML/Script Execution, Tool Abuse)
  - `LLM08_Data-Poisoning/` (RAG Context Poisoning)
- `secure-lib/` reusable LLM security components (scanners, validators, policy, monitoring)
- `controls/`, `governance/`, `compliance/`, `implementation/` placeholders for future expansion

## Quick Start

Pick a lab to run. Each lab has a Vulnerable and a Secured version. For example, to run the LLM01 Secured version:

```bash
cd labs/LLM01_Prompt-Injection/Secured-Version
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
