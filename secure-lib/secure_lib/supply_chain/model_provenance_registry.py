from dataclasses import dataclass


@dataclass
class ProvenanceDecision:
    allowed: bool
    reason: str


class ModelProvenanceRegistry:
    def __init__(self, trusted_publishers: set[str] | None = None, trusted_domains: set[str] | None = None):
        self.trusted_publishers = trusted_publishers or {"trusted-ai-labs", "internal-mlops"}
        self.trusted_domains = trusted_domains or {"registry.internal.ai", "models.example.com"}

    def validate(self, metadata: dict) -> ProvenanceDecision:
        publisher = metadata.get("publisher", "")
        domain = metadata.get("registry_domain", "")
        if publisher not in self.trusted_publishers:
            return ProvenanceDecision(False, "Untrusted publisher.")
        if domain not in self.trusted_domains:
            return ProvenanceDecision(False, "Untrusted registry domain.")
        if not metadata.get("signed_manifest", False):
            return ProvenanceDecision(False, "Signed manifest required.")
        return ProvenanceDecision(True, "Provenance checks passed.")
