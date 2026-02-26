import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Tuple

try:
    import regex
except Exception:  # pragma: no cover - optional runtime dependency
    regex = None

logger = logging.getLogger(__name__)

SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*\S+", re.IGNORECASE)),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("Generic API Key", re.compile(r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?\S{20,}['\"]?")),
    ("Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Private Key Block", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
    ("Database URL", re.compile(r"(?i)(postgres|mysql|mongodb)://\S+:\S+@\S+")),
    ("Slack Token", re.compile(r"xox[bpors]-[0-9A-Za-z\-]{10,}")),
    ("OpenAI Key", re.compile(r"sk-[A-Za-z0-9]{40,}")),
    ("Password in String", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?\S{6,}['\"]?")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
]


@dataclass
class SecretScanResult:
    has_secrets: bool
    findings: List[dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "secret_exposure",
            "detected_by": "secret_detector",
            "action_taken": "blocked" if self.has_secrets else "allowed",
            "findings": self.findings,
        }


class SecretDetector:
    def __init__(self, custom_patterns: List[Tuple[str, re.Pattern]] | None = None):
        self.patterns = list(custom_patterns) if custom_patterns else list(SECRET_PATTERNS)

    def scan(self, text: str) -> SecretScanResult:
        """Scan text for potential secrets."""
        if not text:
            return SecretScanResult(has_secrets=False)

        findings: List[dict] = []
        for label, pattern in self.patterns:
            for match in pattern.findall(text):
                preview = match if len(match) <= 8 else match[:8] + "***REDACTED***"
                findings.append({"type": label, "match_preview": preview})

        result = SecretScanResult(has_secrets=len(findings) > 0, findings=findings)
        if result.has_secrets:
            logger.warning("Secrets detected: %d findings", len(result.findings))
        return result

    def redact(self, text: str) -> str:
        """Replace detected secrets with [REDACTED] placeholders."""
        redacted = text
        for label, pattern in self.patterns:
            redacted = pattern.sub(lambda m: f"[REDACTED:{label}]", redacted)
        return redacted


def detect_secrets(text: str) -> SecretScanResult:
    return SecretDetector().scan(text)
