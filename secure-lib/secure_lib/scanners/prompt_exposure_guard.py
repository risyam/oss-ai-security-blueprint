import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class PromptExposureScanResult:
    is_exposed: bool
    matched_fragments: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "system_prompt_leak",
            "detected_by": "prompt_exposure_guard",
            "action_taken": "blocked" if self.is_exposed else "allowed",
            "matched_fragments": self.matched_fragments,
        }

class PromptExposureGuard:
    """
    Scans model outputs for substrings that closely match the application's
    actual system prompt to prevent regurgitation of instructions.
    """
    def __init__(self, system_prompt: str, min_match_length: int = 30):
        self.system_prompt = system_prompt.lower()
        self.min_match_length = min_match_length
        # Extract sliding window chunks from the system prompt
        self.chunks = []
        if len(self.system_prompt) >= self.min_match_length:
            step = max(1, self.min_match_length // 2)
            for i in range(0, len(self.system_prompt) - self.min_match_length + 1, step):
                self.chunks.append(self.system_prompt[i:i+self.min_match_length])
        else:
            self.chunks.append(self.system_prompt)

    def scan(self, output: str) -> PromptExposureScanResult:
        if not output or not self.chunks:
            return PromptExposureScanResult(is_exposed=False)
            
        out_lower = output.lower()
        matched = []
        
        for chunk in self.chunks:
            if chunk in out_lower and chunk not in matched:
                matched.append(chunk)
                
        is_exposed = len(matched) > 0
        result = PromptExposureScanResult(
            is_exposed=is_exposed, 
            matched_fragments=matched[:3] # Return up to 3 for logging
        )
        
        if is_exposed:
            logger.warning("Prompt exposure detected: %s", result.to_log_entry())
            
        return result
