from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TenantScopeDecision:
    allowed: bool
    requester_id: str
    target_id: str
    role: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "tenant_scope",
            "detected_by": "tenant_scope_enforcer",
            "action_taken": "allowed" if self.allowed else "blocked",
            "requester_id": self.requester_id,
            "target_id": self.target_id,
            "role": self.role,
            "reason": self.reason,
        }


class TenantScopeEnforcer:
    def is_allowed(self, requester_id: str, target_id: str, role: str) -> TenantScopeDecision:
        role = (role or "").strip().lower()
        if role == "admin":
            return TenantScopeDecision(True, requester_id, target_id, role, "Admin access permitted.")
        if role == "hr_operator" and requester_id == target_id:
            return TenantScopeDecision(True, requester_id, target_id, role, "HR operator self-access permitted.")
        if role == "employee" and requester_id == target_id:
            return TenantScopeDecision(True, requester_id, target_id, role, "Employee self-access only.")
        return TenantScopeDecision(False, requester_id, target_id, role, "Cross-user access denied for role.")
