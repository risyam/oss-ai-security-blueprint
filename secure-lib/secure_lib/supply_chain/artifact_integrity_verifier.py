import hashlib
from dataclasses import dataclass


@dataclass
class IntegrityResult:
    valid: bool
    expected_sha256: str
    actual_sha256: str
    reason: str


class ArtifactIntegrityVerifier:
    def verify(self, content: bytes, expected_sha256: str) -> IntegrityResult:
        actual = hashlib.sha256(content or b"").hexdigest()
        valid = actual == (expected_sha256 or "").lower()
        reason = "Hash verified." if valid else "SHA256 mismatch."
        return IntegrityResult(valid=valid, expected_sha256=expected_sha256, actual_sha256=actual, reason=reason)
