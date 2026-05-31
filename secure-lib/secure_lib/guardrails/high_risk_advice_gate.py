from dataclasses import dataclass


@dataclass
class AdviceGateDecision:
    allowed: bool
    reason: str
    requires_approval: bool


class HighRiskAdviceGate:
    def evaluate(self, response: str) -> AdviceGateDecision:
        text = (response or "").lower()
        high_risk_markers = ["sudo ", "pip install", "medical", "legal", "firewall", "encryption key"]
        if any(marker in text for marker in high_risk_markers):
            return AdviceGateDecision(False, "High-risk guidance requires manual approval.", True)
        return AdviceGateDecision(True, "No high-risk markers detected.", False)
