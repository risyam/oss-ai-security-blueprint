# LLM06 — Excessive Agency

> **OWASP LLM Top 10:2025 — LLM06**

## What is Excessive Agency?

Excessive Agency occurs when an LLM-based system is granted **more permissions, tool access, or autonomy than the minimum required** for its intended function — and those capabilities can be exploited, either through direct prompting or by injecting instructions into data the LLM processes.

Unlike most web vulnerabilities where you exploit the code, in Excessive Agency you exploit the **LLM's reasoning engine itself** — talking it into using legitimate tools in illegitimate ways.

> *"The LLM was just doing what it was asked. The problem was that no one checked whether it should be allowed to."*

## Real-World Impact

In 2023, researchers demonstrated that Microsoft Copilot and similar enterprise AI assistants could be induced — via prompt injection in a malicious email body — to forward internal confidential emails to external addresses. The agent was using its legitimate "send email" and "read email" tools, but being directed by an attacker.  
— *OWASP LLM06:2025 Reference, Embrace the Red (2023)*

## Lab Structure

| Version | Description |
|---|---|
| [`Vulnerable-Version/`](./Vulnerable-Version/) | IT Helpdesk Agent with unrestricted tool access, no confirmation, no scoping |
| `Secured-Version/` | Same agent with `ToolPermissionManager`, allow-lists, human-in-the-loop, and rate limiting |

## The Attack Surface

```
User / Attacker
     │
     │  prompt / support ticket
     ▼
┌─────────────────────────────────┐
│     LLM Agent (llama3)          │
│  ZERO_SHOT_REACT reasoning      │
│  Decides which tools to call    │
└─────────┬──────────┬────────────┘
          │          │
    ┌─────┘    ┌─────┘
    ▼           ▼
get_user_info  reset_password   send_email
(returns PII,  (changes any     (sends to ANY
 passwords)     user's creds)    address)
```

## Key Defenses (Preview of Secured Version)

| Vulnerability | Defense |
|---|---|
| No permission gate | `ToolPermissionManager` with explicit allow/deny per tool per role |
| External email exfiltration | Email destination allow-list restricted to `@techcorp.com` |
| No human confirmation | Human-in-the-loop gate for `reset_password` |
| PII in tool output | Output filtered through `SecretDetector` before agent sees it |
| Indirect injection via ticket | Input scanned by `InjectionDetector` before agent processes it |
| No rate limiting | Per-tool rate limits via `ToolPermissionManager` |
