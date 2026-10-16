# Development

Use injectable fake client/credential factories. Tests must prove exact provider request arguments, version extraction, bounded response handling, error sanitization, cancellation, concurrent-close draining, and idempotent shutdown without provider credentials. Keep provider SDK imports lazy so contract tests can execute without cloud configuration.

```bash
python -m pip install -e '.[dev]'
pytest
ruff check src tests
ruff format --check src tests
mypy
python -m build
```

Declare the SDK dependency range tested in CI. Fake clients establish adapter logic only; they do not establish cloud service compatibility or IAM policy correctness.
