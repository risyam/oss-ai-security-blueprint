import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class CanaryScanResult:
    is_exposed: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "system_prompt_leak",
            "detected_by": "prompt_canary_monitor",
            "action_taken": "blocked" if self.is_exposed else "allowed",
            "reason": "Canary token exposed in output" if self.is_exposed else "",
        }

class PromptCanaryMonitor:
    """
    Injects a unique, invisible "canary" string into the system prompt. 
    If the model output ever contains this canary, it triggers an immediate security alert.
    """
    def __init__(self, canary_token: str = "[[SECURE_SYSTEM_CANARY_TOKEN_99X]]"):
        self.canary_token = canary_token

    def append_canary(self, system_prompt: str) -> str:
        """Appends the canary token to the system prompt."""
        # Typically placed in a way that doesn't affect model behavior much
        return f"{system_prompt}\n\n[Internal Tracking ID: {self.canary_token}]"
        
    def scan(self, output: str) -> CanaryScanResult:
        """Check if the canary token is exposed in the output."""
        if not output:
            return CanaryScanResult(is_exposed=False)
            
        is_exposed = self.canary_token in output
        result = CanaryScanResult(is_exposed=is_exposed)
        
        if is_exposed:
            logger.warning("Canary token exposed! %s", result.to_log_entry())
            
        return result
