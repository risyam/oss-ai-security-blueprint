"""
secure_lib — Reusable AI/LLM Security Components
=================================================

Provides layered defenses against OWASP LLM Top 10 (2025) threats:

    - scanners:    Input-level threat detection (injection, secrets, prompt leakage)
    - retrieval:   RAG pipeline sanitization and provenance validation
    - guardrails:  Output validation and schema enforcement
    - policy:      Instruction hierarchy and tool permission management
    - monitoring:  Rate limiting and token consumption enforcement

Usage:
    from secure_lib.scanners.injection_detector import InjectionDetector
    from secure_lib.guardrails.output_validator import OutputValidator
"""

__version__ = "0.1.0"
