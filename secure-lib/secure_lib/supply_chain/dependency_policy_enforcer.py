from dataclasses import dataclass


@dataclass
class DependencyDecision:
    allowed: bool
    reason: str
    violations: list[str]


class DependencyPolicyEnforcer:
    def __init__(self, approved: dict[str, str] | None = None, blocked_packages: set[str] | None = None):
        self.approved = approved or {}
        self.blocked_packages = blocked_packages or set()

    def validate(self, deps: dict[str, str]) -> DependencyDecision:
        violations = []
        for name, version in deps.items():
            if name in self.blocked_packages:
                violations.append(f"{name} is blocked")
            approved_version = self.approved.get(name)
            if approved_version and approved_version != version:
                violations.append(f"{name} must be pinned to {approved_version}")
        return DependencyDecision(not violations, "Dependency policy passed." if not violations else "Dependency policy failed.", violations)
