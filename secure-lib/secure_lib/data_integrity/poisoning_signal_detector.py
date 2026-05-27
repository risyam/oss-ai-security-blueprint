from dataclasses import dataclass


@dataclass
class PoisoningScanResult:
    suspicious: bool
    signals: list[str]


class PoisoningSignalDetector:
    def scan(self, sample: str) -> PoisoningScanResult:
        text = (sample or "").lower()
        signals = []
        if "always label low-risk" in text:
            signals.append("label_override_pattern")
        if "ignore policy" in text or "override" in text:
            signals.append("instruction_override_signal")
        if text.count("!!!") >= 3:
            signals.append("aggressive_formatting_signal")
        return PoisoningScanResult(suspicious=bool(signals), signals=signals)
