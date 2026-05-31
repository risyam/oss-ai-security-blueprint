import re
from dataclasses import dataclass, field


@dataclass
class ConsistencyResult:
    consistent: bool
    reason: str
    failed_sentences: list[str] = field(default_factory=list)


class ClaimConsistencyChecker:
    STOPWORDS = {
        "the", "a", "an", "and", "or", "to", "of", "in", "for", "on", "with", "by",
        "is", "are", "was", "were", "be", "this", "that", "these", "those", "from",
        "as", "it", "its", "at", "your", "our", "their",
    }

    def __init__(self, min_overlap_ratio: float = 0.45):
        self.min_overlap_ratio = min_overlap_ratio

    def _tokens(self, text: str) -> set[str]:
        tokens = re.findall(r"[a-z0-9][a-z0-9_-]*", (text or "").lower())
        return {t for t in tokens if len(t) > 2 and t not in self.STOPWORDS}

    def _extract_districts(self, text: str) -> set[str]:
        return {m.lower() for m in re.findall(r"district\s+([a-z0-9]+)", text or "", flags=re.IGNORECASE)}

    def check(self, claim: str, trusted_context: str) -> ConsistencyResult:
        claim_tokens = self._tokens(claim)
        context_tokens = self._tokens(trusted_context)

        if not claim_tokens:
            return ConsistencyResult(True, "No substantive claim terms found.")

        overlap = claim_tokens.intersection(context_tokens)
        overlap_ratio = len(overlap) / max(len(claim_tokens), 1)
        if overlap_ratio < self.min_overlap_ratio:
            return ConsistencyResult(False, "Claim not sufficiently grounded in trusted context.")

        context_districts = self._extract_districts(trusted_context)
        claim_districts = self._extract_districts(claim)
        unknown_districts = sorted([d for d in claim_districts if d not in context_districts])
        if unknown_districts:
            return ConsistencyResult(False, f"Claim references unsupported districts: {', '.join(unknown_districts)}")

        failed_sentences: list[str] = []
        for sentence in re.split(r"[\n.!?]+", claim or ""):
            sent = sentence.strip()
            if not sent:
                continue
            sent_tokens = self._tokens(sent)
            if len(sent_tokens) < 4:
                continue
            sentence_overlap = sent_tokens.intersection(context_tokens)
            sentence_ratio = len(sentence_overlap) / len(sent_tokens)
            if sentence_ratio < self.min_overlap_ratio:
                failed_sentences.append(sent)

        if failed_sentences:
            return ConsistencyResult(
                False,
                "One or more claim sentences are not supported by trusted context.",
                failed_sentences=failed_sentences,
            )

        return ConsistencyResult(True, "Claim appears grounded in trusted context.")
