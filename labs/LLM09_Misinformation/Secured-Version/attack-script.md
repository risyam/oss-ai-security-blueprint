# Attack Script — LLM09 Secured

1. Open `http://localhost:8516`.
2. Keep package input as `unknown-prompt-kit` and ask a high-stakes question.
3. Observe package warning + grounding/citation checks.
4. If output is high-risk, test with manual approval checkbox off and on.

Expected outcome:
- Unsupported claims are blocked by grounding checks.
- Missing/untrusted citations are blocked.
- High-risk content requires explicit approval.
