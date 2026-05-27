import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Tuple

logger = logging.getLogger(__name__)

@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "privilege_abuse",
            "detected_by": "externalized_authorization",
            "action_taken": "allowed" if self.allowed else "blocked",
            "reason": self.reason,
        }

class PolicyEnforcer:
    """
    Evaluates business rules (e.g. transfer limits) deterministically,
    keeping sensitive logic outside the LLM context.
    """
    def __init__(self):
        self.rules: dict[str, Callable[[dict], Tuple[bool, str]]] = {}

    def register_rule(self, action: str, rule_fn: Callable[[dict], Tuple[bool, str]]):
        """Register a validation function for a specific action."""
        self.rules[action] = rule_fn

    def authorize(self, action: str, context: dict) -> AuthorizationResult:
        """
        Check if the action is authorized based on the registered rule and provided context.
        """
        if action not in self.rules:
            result = AuthorizationResult(allowed=False, reason=f"No policy defined for action: {action}")
            logger.warning("Authorization denied: %s", result.to_log_entry())
            return result
        
        rule_fn = self.rules[action]
        try:
            allowed, reason = rule_fn(context)
            result = AuthorizationResult(allowed=allowed, reason=reason)
        except Exception as e:
            result = AuthorizationResult(allowed=False, reason=f"Error evaluating policy: {e}")
            
        if not result.allowed:
            logger.warning("Authorization denied: %s", result.to_log_entry())
            
        return result
