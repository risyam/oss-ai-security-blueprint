from collections import deque
from dataclasses import dataclass
from time import monotonic


@dataclass
class TrafficAnomalyResult:
    suspicious: bool
    reason: str


class AnomalyTrafficDetector:
    def __init__(self, burst_threshold: int = 5, window_seconds: int = 3):
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        self._events = deque()

    def record_and_check(self) -> TrafficAnomalyResult:
        now = monotonic()
        self._events.append(now)
        while self._events and now - self._events[0] > self.window_seconds:
            self._events.popleft()
        if len(self._events) >= self.burst_threshold:
            return TrafficAnomalyResult(True, "Burst traffic pattern detected.")
        return TrafficAnomalyResult(False, "Traffic normal.")
