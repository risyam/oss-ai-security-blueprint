class RuntimeSecretBroker:
    """
    Manages sensitive information outside the LLM's context.
    Tools retrieve secrets from this broker at execution time instead of
    relying on the LLM to pass them or keeping them in the system prompt.
    """
    def __init__(self):
        self._secrets: dict[str, str] = {}
        
    def register_secret(self, key: str, value: str):
        """Register a secret value for a given key."""
        self._secrets[key] = value
        
    def get_secret(self, key: str) -> str:
        """Retrieve a secret by key. Returns empty string if not found."""
        return self._secrets.get(key, "")
