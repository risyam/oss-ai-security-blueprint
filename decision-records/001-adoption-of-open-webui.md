# ADR 001: Adoption of Open WebUI

## Status
Accepted

## Context
We need a consistent UI layer for demos and internal tooling. Open WebUI provides a fast path to a functional chat UI with local model support and a growing plugin ecosystem.

## Decision
We will use Open WebUI as a reference UI for demos and internal evaluation. Streamlit is retained for lab-style, single-purpose apps.

## Consequences
- Faster demo iteration for stakeholders
- Standard UI for quick tests across models
- Additional dependency and maintenance of Open WebUI-specific configuration
