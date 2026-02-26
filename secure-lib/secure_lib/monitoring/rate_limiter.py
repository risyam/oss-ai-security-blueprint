import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    allowed: bool
    client_id: str
    requests_in_window: int
    limit: int
    window_seconds: int
    retry_after_seconds: float | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "rate_limit",
            "detected_by": "rate_limiter",
            "action_taken": "allowed" if self.allowed else "blocked",
            "client_id": self.client_id,
            "requests_in_window": self.requests_in_window,
            "limit": self.limit,
            "window_seconds": self.window_seconds,
            "retry_after_seconds": self.retry_after_seconds,
        }


class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: Dict[str, List[float]] = {}

    def _clean_window(self, client_id: str) -> List[float]:
        now = time.monotonic()
        window = self._windows.get(client_id, [])
        window = [t for t in window if now - t <= self.window_seconds]
        self._windows[client_id] = window
        return window

    def check(self, client_id: str = "default") -> RateLimitResult:
        """
        Check if a request is allowed for the given client.

        Does NOT consume a request slot — call `record()` after processing.
        """
        window = self._clean_window(client_id)
        if len(window) >= self.max_requests:
            retry_after = (window[0] + self.window_seconds) - time.monotonic()
            result = RateLimitResult(
                allowed=False,
                client_id=client_id,
                requests_in_window=len(window),
                limit=self.max_requests,
                window_seconds=self.window_seconds,
                retry_after_seconds=max(retry_after, 0.0),
            )
            logger.warning("Rate limit exceeded for %s: %s", client_id, result.to_log_entry())
            return result

        return RateLimitResult(
            allowed=True,
            client_id=client_id,
            requests_in_window=len(window),
            limit=self.max_requests,
            window_seconds=self.window_seconds,
        )

    def record(self, client_id: str = "default") -> None:
        window = self._clean_window(client_id)
        window.append(time.monotonic())
        self._windows[client_id] = window

    def check_and_record(self, client_id: str = "default") -> RateLimitResult:
        """Check rate limit and record the request if allowed."""
        result = self.check(client_id=client_id)
        if result.allowed:
            self.record(client_id=client_id)
        return result

    def get_remaining(self, client_id: str = "default") -> int:
        window = self._clean_window(client_id)
        return max(self.max_requests - len(window), 0)

    def reset(self, client_id: str | None = None) -> None:
        if client_id is None:
            self._windows = {}
        else:
            self._windows.pop(client_id, None)
