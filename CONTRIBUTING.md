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

## Commit identity

This is a public repository. New commits must use the project maintainer's
GitHub-provided private address:

    Neil "Soné" Mahure <272403590+croresnos@users.noreply.github.com>

Keep this identity configured globally and in the repository. Before publishing
a branch, verify both author and committer metadata with:

    git log --format="%h %an <%ae> | %cn <%ce>" origin/main..HEAD

Do not override it with a personal or employer-issued email address. Commit
metadata is permanent once it has been published or included in a signed
release.
