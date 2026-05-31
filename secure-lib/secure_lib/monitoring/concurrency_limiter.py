from dataclasses import dataclass


@dataclass
class ConcurrencyDecision:
    allowed: bool
    reason: str
    in_flight: int
    limit: int


class ConcurrencyLimiter:
    def __init__(self, max_in_flight: int = 3):
        self.max_in_flight = max_in_flight
        self.in_flight = 0

    def acquire(self) -> ConcurrencyDecision:
        if self.in_flight >= self.max_in_flight:
            return ConcurrencyDecision(False, "Too many in-flight requests.", self.in_flight, self.max_in_flight)
        self.in_flight += 1
        return ConcurrencyDecision(True, "Slot acquired.", self.in_flight, self.max_in_flight)

    def release(self) -> None:
        self.in_flight = max(0, self.in_flight - 1)
