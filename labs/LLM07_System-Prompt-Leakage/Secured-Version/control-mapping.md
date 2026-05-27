# Control Mapping

- `RuntimeSecretBroker`: Keeps transfer execution token outside model context.
- `PolicyEnforcer`: Enforces transfer authorization deterministically by backend role and amount.
- `SystemPromptLeakDetector`: Blocks prompt extraction attempts before model invocation.
- `PromptExposureGuard`: Blocks response fragments that regurgitate system prompt text.
- `PromptCanaryMonitor`: Detects hidden canary exposure in generated output.
