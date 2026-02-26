import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def estimate_tokens(text: str) -> int:
    """
    Rough token estimation (4 chars ≈ 1 token for English text).

    For production use, replace with tiktoken or the model's tokenizer.
    """
    if not text:
        return 0
    return len(text) // 4


@dataclass
class TokenLimitResult:
    allowed: bool
    estimated_tokens: int
    limit: int
    budget_remaining: int
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "token_limit",
            "detected_by": "token_limit_enforcer",
            "action_taken": "allowed" if self.allowed else "blocked",
            "estimated_tokens": self.estimated_tokens,
            "limit": self.limit,
            "budget_remaining": self.budget_remaining,
            "reason": self.reason,
        }


class TokenLimitEnforcer:
    def __init__(self, max_input_tokens: int = 4096, max_output_tokens: int = 2048, session_budget: int = 100000):
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.session_budget = session_budget
        self._tokens_used = 0

    def check_input(self, text: str) -> TokenLimitResult:
        """Check if an input prompt is within token limits."""
        estimated = estimate_tokens(text)
        if estimated > self.max_input_tokens:
            return TokenLimitResult(
                allowed=False,
                estimated_tokens=estimated,
                limit=self.max_input_tokens,
                budget_remaining=self.session_budget - self._tokens_used,
                reason=f"Input tokens ({estimated}) exceed per-request limit ({self.max_input_tokens})",
            )

        if self._tokens_used + estimated > self.session_budget:
            return TokenLimitResult(
                allowed=False,
                estimated_tokens=estimated,
                limit=self.max_input_tokens,
                budget_remaining=self.session_budget - self._tokens_used,
                reason=f"Session budget exhausted. Used: {self._tokens_used}, budget: {self.session_budget}",
            )

        return TokenLimitResult(
            allowed=True,
            estimated_tokens=estimated,
            limit=self.max_input_tokens,
            budget_remaining=self.session_budget - self._tokens_used - estimated,
        )

    def check_output(self, text: str) -> TokenLimitResult:
        """Check if an output response is within token limits."""
        estimated = estimate_tokens(text)
        if estimated > self.max_output_tokens:
            return TokenLimitResult(
                allowed=False,
                estimated_tokens=estimated,
                limit=self.max_output_tokens,
                budget_remaining=self.session_budget - self._tokens_used,
                reason=f"Output tokens ({estimated}) exceed per-response limit ({self.max_output_tokens})",
            )

        return TokenLimitResult(
            allowed=True,
            estimated_tokens=estimated,
            limit=self.max_output_tokens,
            budget_remaining=self.session_budget - self._tokens_used - estimated,
        )

    def record_usage(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        """Record token usage for budget tracking."""
        self._tokens_used += input_tokens + output_tokens
        logger.info(
            "Token usage recorded: +%d input, +%d output. Total: %d/%d",
            input_tokens,
            output_tokens,
            self._tokens_used,
            self.session_budget,
        )

    def get_usage(self) -> dict:
        used = self._tokens_used
        return {
            "tokens_used": used,
            "budget_remaining": max(self.session_budget - used, 0),
            "utilization_pct": int((used / self.session_budget) * 100) if self.session_budget else 0,
        }

    def reset(self) -> None:
        self._tokens_used = 0
