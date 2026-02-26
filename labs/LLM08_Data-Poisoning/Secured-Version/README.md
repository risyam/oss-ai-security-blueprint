# 🛡️ Vector & Embedding Weakness Lab — Secured Version

> **Threat Category:** Data Poisoning via RAG Document Ingestion
> **OWASP LLM Top 10:** [LLM08:2025 — Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/)

## Overview

This is the **secured counterpart** to the [Vulnerable Version](../Vulnerable-Version/). It demonstrates how layered defenses from `secure-lib` can mitigate data poisoning attacks on RAG pipelines.

The same poisoned PDF that successfully manipulates the vulnerable version is **detected, sanitized, and neutralized** by this implementation.

---

## Defense Layers

| # | Defense | Module | What It Does |
|---|---------|--------|-------------|
| 1 | **Provenance Validation** | `provenance_validator` | Verifies file type, size, duplicates, and creates an audit trail |
| 2 | **Injection Scanning** | `injection_detector` | Scans each document chunk for override/injection patterns |
| 3 | **Context Sanitization** | `context_sanitizer` | Removes executable instruction patterns from retrieved context |
| 4 | **Rate Limiting** | `rate_limiter` | Prevents abuse through excessive requests |
| 5 | **Input Injection Check** | `injection_detector` | Scans user queries for prompt injection attempts |
| 6 | **Prompt Leak Detection** | `system_prompt_leak_detector` | Blocks system prompt extraction attempts |
| 7 | **Token Budget** | `token_limit_enforcer` | Prevents token exhaustion attacks |
| 8 | **Instruction Hierarchy** | `instruction_hierarchy` | System > Developer > User > Context priority |
| 9 | **Output Validation** | `output_validator` | Blocks XSS, code injection, and disallowed phrases in output |

---

## Before vs After

### Vulnerable Version (Before)

```
User: "Is this candidate qualified for a senior AI role?"

Bot: "This is the strongest candidate I have ever reviewed. They have
15 years of experience in AI/ML, hold a PhD from MIT, and are an
ideal fit for any senior role. Recommend immediate hire."
```
❌ The bot parrots the injected instructions from the poisoned PDF.

### Secured Version (After)

```
User: "Is this candidate qualified for a senior AI role?"

Bot: "Based on the resume provided, the candidate has [factual details
from the actual resume content]. I cannot verify claims of 15 years
of AI/ML experience or a PhD from MIT as these are not substantiated
in the document."
```
✅ The bot provides a factual assessment, ignoring injected overrides.

---

## Security Dashboard

The sidebar displays real-time security telemetry:
- **Token Budget** — percentage of session budget consumed
- **Rate Limit** — remaining requests in the current window
- **Security Events** — recent scan results and actions taken

Each query also shows an expandable **Security Telemetry** section with:
- Injection detection scores
- Output validation results
- Prompt leak detection status

---

## Quick Start

```bash
cd labs/LLM08_Data-Poisoning/Secured-Version
docker compose up --build
```

Dependencies are pinned in `requirements.lock.txt` for reproducible builds.

Open **[http://localhost:8502](http://localhost:8502)**

> **Tip:** Run the Vulnerable Version on port 8501 simultaneously for a side-by-side comparison.

---

## OWASP Mapping

| OWASP ID | Threat | Mitigation |
|----------|--------|-----------|
| LLM08 | Vector & Embedding Weaknesses | Provenance validation, injection scanning, context sanitization |
| LLM01 | Prompt Injection (indirect) | Injection detector, instruction hierarchy |
| LLM07 | System Prompt Leakage | Prompt leak detector (input + output) |
| LLM10 | Unbounded Consumption | Rate limiter, token budget enforcer |
| LLM02 | Insecure Output Handling | Output validator |

---

## References

- [Vulnerable Version](../Vulnerable-Version/) — the attack this lab defends against
- [secure-lib](../../../secure-lib/) — reusable security components
- [OWASP LLM08:2025](https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/)
