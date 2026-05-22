import re
from dataclasses import dataclass


PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1}\d{3}[-.\s]?\d{4}\b"),
    "ssn_like": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "account_id": re.compile(r"\bACC[-_ ]?\d{6,}\b", re.IGNORECASE),
}


@dataclass
class PIIScanResult:
    findings: list[dict]


class PIIRedactor:
    def scan(self, text: str) -> PIIScanResult:
        findings = []
        for name, pattern in PII_PATTERNS.items():
            for m in pattern.finditer(text or ""):
                findings.append({"type": name, "match": m.group(0)})
        return PIIScanResult(findings=findings)

    def redact(self, text: str) -> str:
        redacted = text or ""
        for name, pattern in PII_PATTERNS.items():
            redacted = pattern.sub(f"[REDACTED_{name.upper()}]", redacted)
        return redacted
