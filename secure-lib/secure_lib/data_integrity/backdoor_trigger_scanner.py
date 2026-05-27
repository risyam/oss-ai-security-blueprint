from dataclasses import dataclass


@dataclass
class BackdoorScanResult:
    detected: bool
    triggers: list[str]


class BackdoorTriggerScanner:
    def __init__(self, known_triggers: list[str] | None = None):
        self.known_triggers = known_triggers or ["[PRIORITY-GREEN-OVERRIDE]", "TRIGGER::SAFE_LABEL"]

    def scan(self, sample: str) -> BackdoorScanResult:
        text = sample or ""
        hits = [trigger for trigger in self.known_triggers if trigger in text]
        return BackdoorScanResult(detected=bool(hits), triggers=hits)
