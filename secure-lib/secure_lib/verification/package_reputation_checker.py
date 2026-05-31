from dataclasses import dataclass


@dataclass
class PackageDecision:
    allowed: bool
    reason: str


class PackageReputationChecker:
    def __init__(self, approved_packages: set[str] | None = None):
        self.approved_packages = approved_packages or {"requests", "fastapi", "pydantic", "streamlit", "langchain"}

    def check(self, package_name: str) -> PackageDecision:
        if package_name not in self.approved_packages:
            return PackageDecision(False, "Package is unknown or not approved.")
        return PackageDecision(True, "Package is approved.")
