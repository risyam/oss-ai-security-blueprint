import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class SchemaValidationResult:
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    parsed: Dict[str, Any] | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "schema_validation",
            "detected_by": "schema_enforcer",
            "action_taken": "allowed" if self.is_valid else "blocked",
            "errors": self.errors,
        }


class SchemaEnforcer:
    def __init__(self, required_keys: List[str] | None = None):
        self.required_keys = required_keys or []

    def validate_json(self, text: str) -> SchemaValidationResult:
        errors: List[str] = []
        parsed = None
        try:
            parsed = json.loads(text)
        except Exception as exc:
            errors.append(f"Invalid JSON: {exc}")

        if parsed is not None and self.required_keys:
            for key in self.required_keys:
                if key not in parsed:
                    errors.append(f"Missing required key: {key}")

        return SchemaValidationResult(is_valid=len(errors) == 0, errors=errors, parsed=parsed)
