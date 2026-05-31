# Shared Python Dependencies

The labs keep their own `requirements.lock.txt` files so each demo remains reproducible.
The matching `requirements.in` files should reference one of these shared inputs for
common runtime dependencies:

- `common-llm-app.in`: Streamlit, LangChain community/core, and HTTP requests.
- `agent-lab.in`: `common-llm-app.in` plus LangChain and Ollama.
- `rag-lab.in`: `agent-lab.in` plus retrieval/document-ingestion packages.

Regenerate an individual lab lockfile from that lab directory:

```bash
pip-compile --generate-hashes --output-file requirements.lock.txt requirements.in
```

Keep lab-specific or intentionally vulnerable pins in the lab's own `requirements.in`.
