# Contributing

Preflight is a fail-closed security project. Changes should preserve the
distinction between facts known before import and failures discovered after an
import attempt.

## Development

1. Create a Python 3.11 or newer virtual environment.
2. Install the development tools with: python -m pip install -e ".[dev]"
3. Run:

       python -m ruff check .
       python -m ruff format --check .
       python -m mypy
       python -m bandit -q -r src
       python -m pytest --cov

4. Build both archives and audit them:

       python -m build
       python scripts/audit_dist.py dist
       python -m twine check dist/*

Every security fix needs a negative test that fails when the enforcement branch
is weakened. Never include credentials, local agent state, or generated caches
in a commit or distribution.
