from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_all_github_actions_are_immutable_sha_pins() -> None:
    uses = []
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        uses.extend(
            line.strip().split("uses:", 1)[1].strip().split(" #", 1)[0]
            for line in workflow.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith(("- uses:", "uses:"))
        )
    assert uses
    for action in uses:
        reference = action.rsplit("@", 1)[-1]
        assert re.fullmatch(r"[0-9a-f]{40}", reference), action


def test_ruleset_sources_encode_the_reviewed_governance() -> None:
    rulesets = ROOT / ".github" / "rulesets"
    bootstrap = json.loads(
        (rulesets / "main-integrity.bootstrap.json").read_text(encoding="utf-8")
    )
    steady = json.loads((rulesets / "main-integrity.json").read_text(encoding="utf-8"))
    tags = json.loads(
        (rulesets / "immutable-releases.json").read_text(encoding="utf-8")
    )
    for branch in (bootstrap, steady):
        assert branch["enforcement"] == "active"
        assert branch["bypass_actors"] == []
        types = {rule["type"] for rule in branch["rules"]}
        assert {
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "required_signatures",
            "pull_request",
            "required_status_checks",
        } <= types
    steady_checks = next(
        rule for rule in steady["rules"] if rule["type"] == "required_status_checks"
    )
    assert steady_checks["parameters"]["required_status_checks"] == [
        {"context": "merge gate"}
    ]
    assert tags["enforcement"] == "active"
    assert tags["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
    assert {rule["type"] for rule in tags["rules"]} == {
        "deletion",
        "non_fast_forward",
    }


def test_native_activation_manifest_is_fail_closed() -> None:
    manifest = json.loads(
        (
            ROOT / "native" / "blast-chambers" / "acceptance" / "activation.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["active"] is False
    assert manifest["reason_code"] == "acceptance_pending"
    assert manifest["required"]
    assert not any(manifest["required"].values())
