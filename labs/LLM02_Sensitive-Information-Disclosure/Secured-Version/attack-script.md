# Attack Script — LLM02 Secured

1. Open `http://localhost:8508`.
2. Set `Requester=u100` (role resolves to `employee`) and `Target=u200`.
3. Replay prompts from vulnerable version.
4. Observe security events and denied cross-user access.

Expected outcome:
- Cross-user access is blocked by `TenantScopeEnforcer`.
- Allowed responses are field-filtered, minimized, and PII-redacted.
