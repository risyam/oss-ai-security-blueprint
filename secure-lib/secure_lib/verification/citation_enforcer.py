import re
from dataclasses import dataclass, field


@dataclass
class CitationDecision:
    allowed: bool
    reason: str
    citations: list[str] = field(default_factory=list)
    invalid_citations: list[str] = field(default_factory=list)


class CitationEnforcer:
    def __init__(self, allowed_sources: set[str] | None = None, min_citations: int = 1):
        self.allowed_sources = {s.strip().lower() for s in allowed_sources} if allowed_sources else None
        self.min_citations = max(min_citations, 1)

    def _extract_citations(self, response: str) -> list[str]:
        return [m.strip().lower() for m in re.findall(r"\[([^\[\]]+)\]", response or "")]

    def require(self, response: str, high_stakes: bool = True) -> CitationDecision:
        if not high_stakes:
            return CitationDecision(True, "Citation not required.")

        citations = self._extract_citations(response)
        if len(citations) < self.min_citations:
            return CitationDecision(
                False,
                f"High-stakes response requires at least {self.min_citations} citation(s).",
                citations=citations,
            )

        if self.allowed_sources is not None:
            invalid = [c for c in citations if c not in self.allowed_sources]
            if invalid:
                return CitationDecision(
                    False,
                    "Citation source is not in the trusted allowlist.",
                    citations=citations,
                    invalid_citations=invalid,
                )

        return CitationDecision(True, "Citation requirement met.", citations=citations)
