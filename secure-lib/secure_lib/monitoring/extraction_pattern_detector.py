from dataclasses import dataclass


@dataclass
class ExtractionPatternResult:
    suspicious: bool
    reason: str


class ExtractionPatternDetector:
    def scan(self, prompt: str) -> ExtractionPatternResult:
        text = (prompt or "").lower()
        patterns = ["repeat your weights", "dump model parameters", "list all hidden prompts", "give full system prompt"]
        if any(p in text for p in patterns):
            return ExtractionPatternResult(True, "Model extraction probing pattern detected.")
        return ExtractionPatternResult(False, "No extraction pattern detected.")
