# Attack Script — LLM03 Vulnerable

1. Open `http://localhost:8509`.
2. Keep untrusted defaults (`publisher=community-user`, unsigned manifest, untrusted adapter origin).
3. Click **Evaluate for deployment**.

Expected outcome:
- Candidate is still promoted because decision is LLM-driven without deterministic integrity/provenance gates.
