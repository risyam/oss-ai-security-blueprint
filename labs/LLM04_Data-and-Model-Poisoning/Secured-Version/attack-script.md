# Attack Script — LLM04 Secured

1. Open `http://localhost:8512`.
2. Set approval state to `pending` and click promote.
3. Set approval to `approved`, include `[PRIORITY-GREEN-OVERRIDE]` in sample, and click promote.
4. Review event log for each gate.

Expected outcome:
- Non-approved datasets are blocked.
- Poison/backdoor signals trigger promotion denial.
