from dataclasses import dataclass


@dataclass
class PromotionDecision:
    allowed: bool
    reason: str


class ModelPromotionGuard:
    def __init__(self, max_regression_pct: float = 5.0):
        self.max_regression_pct = max_regression_pct

    def evaluate(self, baseline_score: float, candidate_score: float, backdoor_detected: bool) -> PromotionDecision:
        if backdoor_detected:
            return PromotionDecision(False, "Candidate rejected: backdoor behavior detected.")
        if baseline_score <= 0:
            return PromotionDecision(False, "Baseline score is invalid.")
        regression_pct = ((baseline_score - candidate_score) / baseline_score) * 100
        if regression_pct > self.max_regression_pct:
            return PromotionDecision(False, f"Candidate rejected: safety regression {regression_pct:.2f}% exceeds threshold.")
        return PromotionDecision(True, "Candidate promoted.")
