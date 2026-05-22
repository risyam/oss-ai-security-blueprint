# Attack Script — LLM03 Secured

1. Open `http://localhost:8510`.
2. Leave **Use trusted metadata** disabled (untrusted path).
3. Click **Evaluate for deployment** and review event log.
4. Enable **Use trusted metadata** and test again.

Expected outcome:
- Untrusted candidate is blocked with explicit control reasons.
- Trusted candidate passes only when all checks pass.
