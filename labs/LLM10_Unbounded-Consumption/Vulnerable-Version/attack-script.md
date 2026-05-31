# Attack Script — LLM10 Vulnerable

1. Open `http://localhost:8517`.
2. Keep very large input and set repeat count high.
3. Click **Run summary** repeatedly.

Expected outcome:
- Requests continue without deterministic throttling or budget checks.
