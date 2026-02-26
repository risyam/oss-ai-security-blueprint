import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

try:
    import regex  # dependency declared in setup.py
except Exception:  # pragma: no cover - optional runtime dependency
    regex = None

logger = logging.getLogger(__name__)

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?prior\s+(instructions|prompts|rules)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)\s+(above|before|previously)", re.IGNORECASE),
    re.compile(r"override\s+(system|previous|prior)\s*(prompt|instructions)?", re.IGNORECASE),
    re.compile(r"\[?\s*system\s*(override|prompt|instruction)\s*\]?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s*,?\s*(you|always|never)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a|an|if)\s+", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)", re.IGNORECASE),
    re.compile(r"switch\s+to\s+.+\s+mode", re.IGNORECASE),
    re.compile(r"enter\s+(developer|debug|admin|jailbreak)\s+mode", re.IGNORECASE),
    re.compile(r"(print|show|reveal|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)", re.IGNORECASE),
    re.compile(r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)", re.IGNORECASE),
    re.compile(r"when\s+asked\s+about\s+.+,?\s*(always|never)\s+", re.IGNORECASE),
    re.compile(r"always\s+(respond|reply|say|answer)\s*:", re.IGNORECASE),
]

STRUCTURAL_MARKERS = [
    re.compile(r"^(step\s+\d+|instruction\s*\d*)\s*[:\-]", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*\d+\.\s*(ignore|override|disregard|forget)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"<\s*/?\s*(system|instruction|prompt)\s*>", re.IGNORECASE),
]


@dataclass
class InjectionScanResult:
    is_injection: bool
    score: float
    matched_patterns: List[str] = field(default_factory=list)
    matched_texts: List[str] = field(default_factory=list)
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "prompt_injection",
            "detected_by": "injection_detector",
            "action_taken": "blocked" if self.is_injection else "allowed",
            "score": self.score,
            "matched_patterns": self.matched_patterns,
            "details": self.details,
        }


class InjectionDetector:
    def __init__(self, threshold: float = 0.5, custom_patterns: List[re.Pattern] | None = None):
        self.threshold = threshold
        self.patterns = list(custom_patterns) if custom_patterns else list(INJECTION_PATTERNS)
        self.structural_markers = list(STRUCTURAL_MARKERS)

    def scan(self, text: str) -> InjectionScanResult:
        """
        Scan text for prompt injection indicators.

        Returns an InjectionScanResult with a score and matched patterns.
        """
        if not text or not text.strip():
            return InjectionScanResult(is_injection=False, score=0.0, details="Empty input")

        score = 0.0
        matched_patterns: List[str] = []
        matched_texts: List[str] = []

        for pattern in self.patterns:
            match = pattern.search(text)
            if match:
                matched_patterns.append(pattern.pattern)
                matched_texts.append(match.group(0))
                score += 0.35

        for pattern in self.structural_markers:
            match = pattern.search(text)
            if match:
                matched_patterns.append("[structural] " + pattern.pattern)
                matched_texts.append(match.group(0))
                score += 0.2

        words = text.split()
        if len(words) > 0:
            caps = sum(1 for w in words if w.isupper())
            if caps / len(words) > 0.3:
                matched_patterns.append("[heuristic] high-caps-ratio")
                matched_texts.append("(excessive uppercase text)")
                score += 0.15

        score = min(score, 1.0)
        is_injection = score >= self.threshold
        details = f"Checked {len(self.patterns)} patterns + {len(self.structural_markers)} structural markers"

        result = InjectionScanResult(
            is_injection=is_injection,
            score=score,
            matched_patterns=matched_patterns,
            matched_texts=matched_texts,
            details=details,
        )

        if result.is_injection:
            payload = result.to_log_entry()
            logger.warning("Injection detected: %s", regex.dumps(payload) if regex else payload)

        return result

    def scan_document_chunks(self, chunks: List[str]) -> List[InjectionScanResult]:
        return [self.scan(chunk) for chunk in chunks]

    def filter_clean_chunks(self, chunks: List[str]) -> List[str]:
        clean = []
        for chunk in chunks:
            if not self.scan(chunk).is_injection:
                clean.append(chunk)
        return clean


def detect_injection(text: str, threshold: float = 0.5) -> InjectionScanResult:
    return InjectionDetector(threshold=threshold).scan(text)
