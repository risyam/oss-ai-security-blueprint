from dataclasses import dataclass


@dataclass
class AdapterDecision:
    allowed: bool
    reason: str


class LoraAdapterPolicy:
    def __init__(self, trusted_origins: set[str] | None = None, compatible_bases: set[str] | None = None):
        self.trusted_origins = trusted_origins or {"registry.internal.ai", "adapters.example.com"}
        self.compatible_bases = compatible_bases or {"llama3", "mistral"}

    def validate(self, adapter_metadata: dict, base_model: str) -> AdapterDecision:
        if adapter_metadata.get("origin") not in self.trusted_origins:
            return AdapterDecision(False, "Adapter origin is not trusted.")
        if base_model not in self.compatible_bases:
            return AdapterDecision(False, "Adapter/base model compatibility not allowed.")
        return AdapterDecision(True, "Adapter policy checks passed.")
