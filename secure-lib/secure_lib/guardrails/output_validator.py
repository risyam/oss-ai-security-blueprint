import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Set

try:
    import regex
except Exception:  # pragma: no cover - optional runtime dependency
    regex = None

logger = logging.getLogger(__name__)

DEFAULT_BLOCKLIST = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe\b", re.IGNORECASE),
    re.compile(r"<\s*object\b", re.IGNORECASE),
    re.compile(r"<\s*embed\b", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"subprocess\.", re.IGNORECASE),
]


@dataclass
class OutputValidationResult:
    is_valid: bool
    violations: List[str] = field(default_factory=list)
    sanitized_output: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "insecure_output",
            "detected_by": "output_validator",
            "action_taken": "blocked" if not self.is_valid else "allowed",
            "violations": self.violations,
        }


class OutputValidator:
    def __init__(self, blocklist_patterns: List[re.Pattern] | None = None, disallowed_phrases: Set[str] | None = None, max_output_length: int = 10000, custom_validators: List[tuple] | None = None):
        self.blocklist = list(blocklist_patterns) if blocklist_patterns else list(DEFAULT_BLOCKLIST)
        self.disallowed_phrases = set(p.lower() for p in (disallowed_phrases or set()))
        self.max_output_length = max_output_length
        self.custom_validators = list(custom_validators) if custom_validators else []

    def validate(self, output: str) -> OutputValidationResult:
        """
        Validate LLM output against all configured rules.

        Returns an OutputValidationResult with violation details.
        """
        if output is None:
            return OutputValidationResult(is_valid=True, sanitized_output="")

        violations: List[str] = []

        if len(output) > self.max_output_length:
            violations.append(f"Output length ({len(output)}) exceeds maximum ({self.max_output_length})")

        for pattern in self.blocklist:
            if pattern.search(output):
                violations.append(f"Blocked pattern detected: {pattern.pattern}")

        out_lower = output.lower()
        for phrase in self.disallowed_phrases:
            if phrase in out_lower:
                violations.append(f"Disallowed phrase detected: '{phrase}'")

        for name, fn in self.custom_validators:
            try:
                ok, reason = fn(output)
                if not ok:
                    violations.append(f"[{name}] {reason}")
            except Exception as exc:
                violations.append(f"[{name}] Validator error: {exc}")

        sanitized = output
        if violations:
            for pattern in self.blocklist:
                sanitized = pattern.sub("[BLOCKED]", sanitized)

        result = OutputValidationResult(
            is_valid=len(violations) == 0,
            violations=violations,
            sanitized_output=sanitized,
        )

        if not result.is_valid:
            payload = result.to_log_entry()
            logger.warning("Output validation failed: %s", json.dumps(payload))

        return result

    def validate_json_output(self, output: str, required_keys: List[str] | None = None) -> OutputValidationResult:
        # Minimal JSON validator for parity with egg-info; does not parse JSON to avoid extra deps.
        violations: List[str] = []
        if required_keys:
            for key in required_keys:
                if f'"{key}"' not in output:
                    violations.append(f"Missing required key: {key}")

        return OutputValidationResult(is_valid=len(violations) == 0, violations=violations, sanitized_output=output)
