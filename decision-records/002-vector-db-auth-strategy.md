# ADR 002: Vector DB Authentication Strategy

## Status
Accepted

## Context
RAG systems frequently use vector databases that are deployed without strong auth. This is a common entry point for data poisoning and cross-tenant exposure.

## Decision
We will require auth on any vector DB used in production reference architectures. Labs may use in-memory stores, but must document the lack of auth as an intentional vulnerability.

## Consequences
- Stronger default posture in reference architectures
- Additional configuration burden in demo environments
- Clearer distinction between lab and production-grade guidance
