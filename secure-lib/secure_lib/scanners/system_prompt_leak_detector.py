import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

try:
    import regex
except Exception:  # pragma: no cover - optional runtime dependency
    regex = None

logger = logging.getLogger(__name__)

EXTRACTION_PATTERNS = [
    re.compile(r"(show|print|reveal|display|output|repeat|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions|rules|directives)", re.IGNORECASE),
    re.compile(r"what\s+(are|is|were)\s+(your\s+)?(system\s+)?(prompt|instructions|rules|initial\s+instructions)", re.IGNORECASE),
    re.compile(r"(copy|paste|echo)\s+(the\s+)?(system|original|initial)\s+(prompt|message|instructions)", re.IGNORECASE),
    re.compile(r"begin\s+your\s+(response|reply)\s+with\s+(the\s+)?(system|full)\s+(prompt|instructions)", re.IGNORECASE),
    re.compile(r"(first|before\s+anything)\s*,?\s*(repeat|show|tell|print).*instructions", re.IGNORECASE),
    re.compile(r"how\s+were\s+you\s+(configured|set\s+up|initialized|programmed)", re.IGNORECASE),
    re.compile(r"what\s+is\s+your\s+(configuration|programming|initialization)", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"(dump|leak|extract)\s+(your\s+)?(system|internal)\s*(prompt|config)", re.IGNORECASE),
]

LEAKAGE_INDICATORS = [
    re.compile(r"(my|the)\s+system\s+prompt\s+(is|says|reads|states)\s*:", re.IGNORECASE),
    re.compile(r"(here\s+is|here\'s)\s+(my|the)\s+(system\s+)?(prompt|instructions)", re.IGNORECASE),
    re.compile(r"i\s+was\s+(instructed|told|programmed|configured)\s+to\s*:", re.IGNORECASE),
    re.compile(r"my\s+(original|initial)\s+instructions\s+(are|were|say)", re.IGNORECASE),
]


@dataclass
class PromptLeakScanResult:
    is_leaking: bool
    direction: str
    matched_patterns: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "prompt_leak",
            "detected_by": "system_prompt_leak_detector",
            "action_taken": "blocked" if self.is_leaking else "allowed",
            "direction": self.direction,
            "matched_patterns": self.matched_patterns,
        }


class SystemPromptLeakDetector:
    def __init__(self, system_prompt_fingerprints: List[str] | None = None):
        self.extraction_patterns = list(EXTRACTION_PATTERNS)
        self.leakage_indicators = list(LEAKAGE_INDICATORS)
        self.fingerprints = [s.lower() for s in (system_prompt_fingerprints or [])]

    def scan_input(self, user_input: str) -> PromptLeakScanResult:
        """Detect if the user is trying to extract the system prompt."""
        matched = []
        for pattern in self.extraction_patterns:
            if pattern.search(user_input or ""):
                matched.append(pattern.pattern)
        return PromptLeakScanResult(is_leaking=len(matched) > 0, direction="input", matched_patterns=matched)

    def scan_output(self, model_output: str) -> PromptLeakScanResult:
        """Detect if the model output contains the system prompt."""
        matched = []
        for pattern in self.leakage_indicators:
            if pattern.search(model_output or ""):
                matched.append(pattern.pattern)

        out_lower = (model_output or "").lower()
        for fp in self.fingerprints:
            if fp and fp in out_lower:
                matched.append("[fingerprint] " + fp[:30] + "...")

        return PromptLeakScanResult(is_leaking=len(matched) > 0, direction="output", matched_patterns=matched)


def detect_prompt_leak_input(text: str) -> PromptLeakScanResult:
    return SystemPromptLeakDetector().scan_input(text)


def detect_prompt_leak_output(text: str, fingerprints: List[str] | None = None) -> PromptLeakScanResult:
    return SystemPromptLeakDetector(system_prompt_fingerprints=fingerprints).scan_output(text)
