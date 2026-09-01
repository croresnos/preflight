"""Release archives must never carry developer state or likely credentials."""

from __future__ import annotations

import pytest

from scripts.audit_dist import validate_name


@pytest.mark.parametrize(
    "name",
    [
        "package/.env",
        "package/.env.production",
        "package/.preflight/approvals.json",
        "package/audit.key",
        "package/evidence.jsonl",
        "package/private.pem",
        "package/signing.p12",
        "package/.vscode/settings.json",
        "package/.DS_Store",
        "package/Thumbs.db",
        "package/._README.md",
    ],
)
def test_release_audit_refuses_local_or_secret_bearing_paths(name: str) -> None:
    assert validate_name(name) is not None


@pytest.mark.parametrize(
    "name",
    [
        "package/.env.example",
        "package/preflight.toml",
        "package/preflight.lock",
        "package/src/preflight/trust.py",
    ],
)
def test_release_audit_keeps_committed_policy_and_safe_source(name: str) -> None:
    assert validate_name(name) is None
