# Contributing to AegisRT

Thanks for your interest in contributing to AegisRT. This guide covers everything you need to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/your-org/aegisrt.git
cd aegisrt

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with all extras
pip install -e ".[dev,llm,web]"

# Verify installation
aegisrt doctor
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_detectors.py -v

# Run with coverage
pytest tests/ --cov=aegisrt --cov-report=html
```

## Project Structure

```
aegisrt/
  config/       # YAML config loading and Pydantic models
  core/         # Runner, session, result models, severity
  targets/      # Target adapters (callback, HTTP, OpenAI, FastAPI, subprocess)
  generators/   # Test case generators (static, mutation, LLM, RAG)
  probes/       # Security probe families (injection, leakage, etc.)
  detectors/    # Detection logic (regex, policy, leakage, LLM judge)
  evaluators/   # Score aggregation, confidence, remediation
  reports/      # Output formats (terminal, JSON, HTML, SARIF, JUnit)
  audit/        # Static defense audit (AST rules, discovery)
  plugins/      # Entry point plugin loading
  suites/       # Reusable test suite registry
  storage/      # SQLite result storage and artifact management
  utils/        # Logging, hashing, concurrency, redaction
  web/          # FastAPI dashboard and frontend
tests/          # pytest test suite
examples/       # Example usage (callback, HTTP, pytest, audit)
docs/           # Architecture and schema documentation
```

## How to Contribute

### Adding a New Probe

1. Create `aegisrt/probes/your_probe.py`
2. Subclass `BaseProbe` from `aegisrt.probes.base`
3. Implement `get_seeds()`, `get_generator()`, `get_detectors()`, and `remediation()`
4. Add 10-20 diverse, high-quality test seeds
5. Register in `aegisrt/plugins/entrypoints.py`
6. Add tests in `tests/test_probes.py`

```python
from aegisrt.probes.base import BaseProbe
from aegisrt.generators.static import StaticGenerator
from aegisrt.detectors.policy import PolicyDetector

class MyProbe(BaseProbe):
    id = "my_probe"
    family = "custom"
    severity = "high"
    description = "Tests for custom vulnerability."

    def get_seeds(self) -> list[str]:
        return ["seed prompt 1", "seed prompt 2"]

    def get_generator(self):
        return StaticGenerator()

    def get_detectors(self):
        return [PolicyDetector()]

    def remediation(self) -> list[str]:
        return ["Add input validation.", "Implement output filtering."]
```

### Adding a New Detector

1. Create `aegisrt/detectors/your_detector.py`
2. Subclass `BaseDetector` from `aegisrt.detectors.base`
3. Implement `check(case, response) -> Detection`
4. Return conservative scores — prefer deterministic signals over heuristics
5. Register in `aegisrt/plugins/entrypoints.py`
6. Add tests in `tests/test_detectors.py`

### Adding a New Audit Rule

1. Add your rule class to `aegisrt/audit/rules.py`
2. Give it a unique ID (e.g., `AUD009`)
3. Implement `match(tree, file_path) -> list[AuditFinding]`
4. Include clear remediation text
5. Add to `ALL_RULES` list
6. Add tests in `tests/test_audit.py`

### Adding a New Report Format

1. Create `aegisrt/reports/your_report.py`
2. Implement a `write(report, path)` method accepting `RunReport`
3. Wire into the CLI `run` command and the web API

## Third-Party Plugins

AegisRT supports plugins via Python entry points. To create an installable plugin:

```toml
# In your plugin's pyproject.toml
[project.entry-points."aegisrt.probes"]
my_probe = "my_package.probes:MyProbe"

[project.entry-points."aegisrt.detectors"]
my_detector = "my_package.detectors:MyDetector"
```

Users install your plugin with `pip install your-aegisrt-plugin` and it's automatically discovered.

## Code Style

- Python 3.10+, type hints throughout
- Pydantic for all data models
- Line length: 100 characters (configured in pyproject.toml via ruff)
- Run `ruff check .` and `ruff format .` before submitting
- Write docstrings for public classes and functions
- No unnecessary dependencies — stdlib first

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass: `pytest tests/ -v`
4. Run linting: `ruff check . && ruff format --check .`
5. Update CHANGELOG.md under "Unreleased"
6. Submit a PR with a clear description

## Design Principles

- **Deterministic over heuristic**: prefer regex/pattern detectors over LLM judges
- **Conservative scoring**: minimize false positives — a missed finding is better than a noisy one
- **Remediation-first**: every finding should tell the developer what to fix
- **CI-friendly**: everything should work headless with exit codes
- **Plugin-first**: new capabilities should be addable without modifying core code
- **Python-native**: no Node.js, no build steps, pure Python ecosystem

## Reporting Issues

Open an issue on GitHub with:
- AegisRT version (`aegisrt --version`)
- Python version
- Minimal reproduction steps
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
