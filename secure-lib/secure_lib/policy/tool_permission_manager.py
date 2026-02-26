import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


@dataclass
class ToolPolicy:
    name: str
    allowed: bool = True
    max_calls_per_session: int = 50
    allowed_arguments: Dict[str, Set[str]] | None = None
    requires_confirmation: bool = False
    description: str = ""


@dataclass
class ToolInvocationResult:
    allowed: bool
    tool_name: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "tool_invocation",
            "detected_by": "tool_permission_manager",
            "action_taken": "allowed" if self.allowed else "blocked",
            "tool_name": self.tool_name,
            "reason": self.reason,
        }


class ToolPermissionManager:
    def __init__(self, default_deny: bool = True):
        self.default_deny = default_deny
        self._policies: Dict[str, ToolPolicy] = {}
        self._audit_log: List[dict] = []
        self._call_counts: Dict[str, int] = {}

    def register_tool(self, policy: ToolPolicy) -> None:
        self._policies[policy.name] = policy

    def register_tools(self, policies: List[ToolPolicy]) -> None:
        for policy in policies:
            self.register_tool(policy)

    def get_allowed_tools(self) -> List[str]:
        return [name for name, p in self._policies.items() if p.allowed]

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)

    def reset_session(self) -> None:
        self._call_counts = {}
        self._audit_log = []

    def check_permission(self, tool_name: str, arguments: Dict[str, Any] | None = None) -> ToolInvocationResult:
        """
        Check if a tool invocation is permitted.

        Returns a ToolInvocationResult with the decision and reason.
        """
        policy = self._policies.get(tool_name)
        if policy is None:
            result = ToolInvocationResult(
                allowed=not self.default_deny,
                tool_name=tool_name,
                reason="Tool not registered. " + ("Default deny." if self.default_deny else "Default allow."),
            )
            self._audit_log.append(result.to_log_entry())
            return result

        if not policy.allowed:
            result = ToolInvocationResult(
                allowed=False,
                tool_name=tool_name,
                reason="Tool is explicitly disabled by policy.",
            )
            self._audit_log.append(result.to_log_entry())
            return result

        count = self._call_counts.get(tool_name, 0)
        if count >= policy.max_calls_per_session:
            result = ToolInvocationResult(
                allowed=False,
                tool_name=tool_name,
                reason=f"Rate limit exceeded: {count}/{policy.max_calls_per_session} calls.",
            )
            self._audit_log.append(result.to_log_entry())
            return result

        if policy.allowed_arguments and arguments:
            for key, allowed_vals in policy.allowed_arguments.items():
                if key in arguments and arguments[key] not in allowed_vals:
                    result = ToolInvocationResult(
                        allowed=False,
                        tool_name=tool_name,
                        reason=f"Argument '{key}' value '{arguments[key]}' not in allowed set: {allowed_vals}",
                    )
                    self._audit_log.append(result.to_log_entry())
                    return result

        self._call_counts[tool_name] = count + 1
        result = ToolInvocationResult(
            allowed=True,
            tool_name=tool_name,
            reason="Permitted by policy.",
        )
        self._audit_log.append(result.to_log_entry())
        return result
