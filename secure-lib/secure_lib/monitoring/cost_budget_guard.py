from dataclasses import dataclass


@dataclass
class BudgetDecision:
    allowed: bool
    reason: str
    used: float
    budget: float


class CostBudgetGuard:
    def __init__(self, budget_usd: float = 2.0):
        self.budget_usd = budget_usd
        self.used_usd = 0.0

    def check(self, estimated_cost: float) -> BudgetDecision:
        if self.used_usd + estimated_cost > self.budget_usd:
            return BudgetDecision(False, "Cost budget exceeded.", self.used_usd, self.budget_usd)
        return BudgetDecision(True, "Within budget.", self.used_usd, self.budget_usd)

    def record(self, cost: float) -> None:
        self.used_usd += max(cost, 0.0)
