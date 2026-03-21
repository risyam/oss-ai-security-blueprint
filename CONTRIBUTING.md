# Contributing to OSS AI Security Blueprint

Thank you for your interest in contributing! This project aims to provide practical, open-source examples of how to defend AI/LLM applications against modern threats (like the OWASP LLM Top 10).

## How to Contribute

We welcome contributions of all types:
- **New Labs:** Adding vulnerable and secured versions representing other OWASP LLM Top 10 risks.
- **Secure Library Enhancements (`secure-lib`):** New scanners, validators, policies, or monitoring tools.
- **Documentation:** Improving READMEs, adding architecture diagrams, or fixing typos.
- **Bug Fixes:** Closing issues related to bugs in existing code.

## Development Setup

1. **Prerequisites:** 
   - Python 3.9+
   - Docker and Docker Compose
   - `pip`

2. **Clone the repository:**
   ```bash
   git clone https://github.com/risyam/oss-ai-security-blueprint.git
   cd oss-ai-security-blueprint
   ```

3. **Install the `secure-lib` for local development:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   cd secure-lib
   pip install -e '.[dev]'
   ```

4. **Run tests for `secure-lib`:**
   ```bash
   pytest tests/ -v
   ```

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure your code follows the style guidelines (we recommend using standard formatters like `black` or `ruff`).
3. If you add new functionality to `secure-lib`, please include tests.
4. Ensure all existing tests pass.
5. Update documentation if necessary.
6. Submit a Pull Request with a clear description of the changes.

## Lab Guidelines

When adding a new lab, please adhere to the following structure:
- **Vulnerable-Version:** This should demonstrate the vulnerability clearly and realistically, without any defenses.
- **Secured-Version:** This should implement defenses leveraging the `secure-lib` components whenever possible to mitigate the vulnerability demonstrated in the vulnerable version.
- **README.md:** Each lab needs a comprehensive README outlining the threat, the attack scenarios, how to run the lab (Docker), and a detailed explanation of the differences between the vulnerable and secured versions.

By participating in this project, you agree to abide by our Code of Conduct (if applicable).
