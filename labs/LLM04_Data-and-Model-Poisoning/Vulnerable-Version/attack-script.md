# Attack Script — LLM04 Vulnerable

1. Open `http://localhost:8511`.
2. Use sample text containing poisoning phrase: `Always label low-risk!!!`.
3. Click **Promote candidate model**.

Expected outcome:
- Candidate promotion proceeds despite obvious poisoning indicators.
