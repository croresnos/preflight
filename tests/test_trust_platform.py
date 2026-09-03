from __future__ import annotations

import io
import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from preflight import trust_cli
from preflight.artifacts import ArtifactError, identify_artifact
from preflight.backends import AlphaBackend
from preflight.cli import main
from preflight.policy import evaluate
from preflight.project import (
    ProjectError,
    activate_project,
    append_evidence,
    grant_approval,
    matching_approval,
    read_evidence,
    read_lock,
    read_policy,
    revoke_approval,
    write_lock,
)
from preflight.trust import (
    ArtifactIdentity,
    ArtifactKind,
    BackendCapabilities,
    CapabilitySet,
    DependencyGraph,
    FileAccess,
    IsolationTier,
    ReasonCode,
    trust_json_schema,
)


@pytest.fixture
def local_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "local-data"
    monkeypatch.setattr("preflight.project.local_data_root", lambda: state)
    return state


def _graph(digest: str = "a" * 64) -> DependencyGraph:
    return DependencyGraph(
        root=ArtifactIdentity(
            kind=ArtifactKind.WHEEL,
            source="example.whl",
            content_sha256=digest,
            size=42,
        )
    )


def _backend(*tiers: IsolationTier) -> BackendCapabilities:
    standard = IsolationTier.STANDARD in tiers
    return BackendCapabilities(
        backend_id="test/1",
        platform="win32",
        available_tiers=tiers,
        filesystem_enforced=standard,
        network_enforced=standard,
        credential_isolation=standard,
        process_isolation=standard,
        resource_limits=standard,
        independent_kernel=IsolationTier.MAXIMUM in tiers,
    )


def test_capability_selectors_are_required_and_digest_is_stable() -> None:
    with pytest.raises(ValidationError, match="file_paths"):
        CapabilitySet(files=FileAccess.READ_SELECTED)
    first = CapabilitySet(
        files=FileAccess.READ_SELECTED,
        file_paths=("docs",),
    )
    second = CapabilitySet.model_validate(first.model_dump(mode="json"))
    assert first.digest == second.digest


def test_trust_schema_bundle_is_versioned_and_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    schema = trust_json_schema()
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["x-preflight-format"] == 1
    assert "PolicyDecision" in schema["$defs"]
    assert "ApprovalRequest" in schema["$defs"]
    assert "ProvenanceRecord" in schema["$defs"]
    assert main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out)["$id"].endswith("trust-v1.json")


def test_directory_identity_is_stable_and_changes_with_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("first", encoding="utf-8")
    first = identify_artifact(source)
    assert first == identify_artifact(source)
    (source / "a.txt").write_text("second", encoding="utf-8")
    assert identify_artifact(source).content_sha256 != first.content_sha256


def test_artifact_identity_rejects_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")
    link = source / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this host does not permit test symlinks")
    with pytest.raises(ArtifactError, match="symlink"):
        identify_artifact(source)


def test_lock_digest_detects_tampering(tmp_path: Path) -> None:
    graph = _graph()
    write_lock(tmp_path, graph)
    payload = json.loads((tmp_path / "preflight.lock").read_text(encoding="utf-8"))
    payload["graph"]["root"]["size"] = 43
    (tmp_path / "preflight.lock").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProjectError, match="digest does not match"):
        read_lock(tmp_path)


def test_approval_is_bound_to_every_material_input(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    graph = _graph()
    grant = grant_approval(policy, graph, tier=IsolationTier.RESOURCE_ONLY)
    assert matching_approval(policy, graph, IsolationTier.RESOURCE_ONLY) == grant
    changed = _graph("b" * 64)
    assert matching_approval(policy, changed, IsolationTier.RESOURCE_ONLY) is None
    assert matching_approval(policy, graph, IsolationTier.STANDARD) is None

    revoke_approval(policy, grant.approval_id)
    assert matching_approval(policy, graph, IsolationTier.RESOURCE_ONLY) is None


def test_evidence_chain_detects_any_modified_record(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    append_evidence(policy, "test.event", {"answer": 42})
    assert len(read_evidence(policy)) == 2

    evidence = local_state / "projects" / policy.project_id / "evidence.jsonl"
    value = evidence.read_text(encoding="utf-8").replace("42", "43")
    evidence.write_text(value, encoding="utf-8")
    with pytest.raises(ProjectError, match="verification failed"):
        read_evidence(policy)


def test_policy_never_silently_downgrades(tmp_path: Path, local_state: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    graph = _graph()
    grant_approval(policy, graph, tier=IsolationTier.STANDARD)

    decision = evaluate(
        policy,
        graph,
        _backend(IsolationTier.RESOURCE_ONLY),
        requested_tier=IsolationTier.STANDARD,
    )
    assert not decision.allowed
    assert decision.achieved_tier is None
    assert ReasonCode.BACKEND_UNAVAILABLE in {
        reason.code for reason in decision.reasons
    }
    assert ReasonCode.DOWNGRADE_REQUIRED in {reason.code for reason in decision.reasons}


def test_exact_approval_allows_only_the_requested_available_tier(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    graph = _graph()
    grant_approval(policy, graph, tier=IsolationTier.STANDARD)
    decision = evaluate(
        policy,
        graph,
        _backend(IsolationTier.STANDARD),
        requested_tier=IsolationTier.STANDARD,
    )
    assert decision.allowed
    assert decision.achieved_tier is IsolationTier.STANDARD
    assert decision == evaluate(
        policy,
        graph,
        _backend(IsolationTier.STANDARD),
        requested_tier=IsolationTier.STANDARD,
    )


def test_alpha_backend_reports_weakness_instead_of_claiming_a_sandbox() -> None:
    capabilities = AlphaBackend().capabilities()
    assert capabilities.available_tiers == (IsolationTier.RESOURCE_ONLY,)
    assert not capabilities.filesystem_enforced
    assert not capabilities.network_enforced
    assert not capabilities.credential_isolation
    assert not capabilities.process_isolation
    assert not capabilities.resource_limits


def test_cli_requires_opt_in_then_byte_bound_explicit_downgrade(
    tmp_path: Path,
    local_state: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    source = tmp_path / "source"
    project.mkdir()
    source.mkdir()
    (source / "payload.txt").write_text("v1", encoding="utf-8")

    entrypoint = [sys.executable, "-c", "print('must not run')"]
    install_args = [
        "install",
        str(source),
        "--project",
        str(project),
        "--entrypoint",
        *entrypoint,
    ]
    assert main(install_args) == 2
    assert "UNPROTECTED" in capsys.readouterr().err
    assert main(["on", str(project)]) == 0
    assert main(install_args) == 1
    staged = capsys.readouterr().out
    assert "STAGED (NOT INSTALLED)" in staged
    assert "no candidate code was executed" in staged

    assert (
        main(
            [
                "approve",
                "--tier",
                "resource-only",
                "--project",
                str(project),
            ]
        )
        == 2
    )
    assert "accept-weaker-isolation" in capsys.readouterr().err
    assert (
        main(
            [
                "approve",
                "--tier",
                "resource-only",
                "--accept-weaker-isolation",
                "--project",
                str(project),
            ]
        )
        == 0
    )

    (source / "payload.txt").write_text("v2", encoding="utf-8")
    result = main(
        [
            "run",
            "--tier",
            "resource-only",
            "--accept-weaker-isolation",
            "--project",
            str(project),
            "--",
            *entrypoint,
        ]
    )
    assert result == 2
    assert "artifact bytes changed" in capsys.readouterr().err


def test_project_policy_is_committed_but_local_security_state_is_not(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    activated = activate_project(project)
    loaded = read_policy(project)
    assert loaded == activated
    assert (project / "preflight.toml").is_file()
    assert not (project / ".preflight").exists()
    assert (local_state / "projects" / activated.project_id / "audit.key").is_file()


def test_project_identity_cannot_escape_the_local_state_root(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "preflight.toml").write_text(
        "format = 1\n"
        "project_id = '../../outside'\n"
        "active = true\n"
        "policy_version = 1\n"
        "default_tier = 'standard'\n"
        "spending = 'deny'\n"
        "[capabilities]\n",
        encoding="utf-8",
    )
    with pytest.raises(ProjectError, match="project_id"):
        read_policy(project)
    assert not (tmp_path / "outside").exists()


def test_project_security_files_may_not_be_symlinks(
    tmp_path: Path, local_state: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    lock = project / "preflight.lock"
    try:
        lock.symlink_to(target)
    except OSError:
        pytest.skip("this host does not permit test symlinks")
    with pytest.raises(ProjectError, match="may not be a symlink"):
        read_lock(project)

    lock.unlink()
    approvals = local_state / "projects" / policy.project_id / "approvals.json"
    approvals.symlink_to(target)
    with pytest.raises(ProjectError, match="may not be a symlink"):
        grant_approval(policy, _graph(), tier=IsolationTier.RESOURCE_ONLY)


def test_cli_lifecycle_records_decisions_and_runs_only_the_exact_artifact(
    tmp_path: Path,
    local_state: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust_cli, "default_backend", AlphaBackend)
    project = tmp_path / "project"
    source = tmp_path / "source"
    project.mkdir()
    source.mkdir()
    (source / "payload.txt").write_text("stable", encoding="utf-8")

    assert main(["status", str(project), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "unprotected"
    assert main(["on", str(project)]) == 0
    capsys.readouterr()
    assert main(["status", str(project), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "active"
    assert status["evidence_records"] == 1
    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["available_tiers"] == ["resource-only"]

    locked_command = [sys.executable, "-c", "print('contained-contract')"]
    assert (
        main(
            [
                "install",
                str(source),
                "--project",
                str(project),
                "--entrypoint",
                *locked_command,
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert main(["deny", "--reason", "not yet", "--project", str(project)]) == 0
    assert "DENIED" in capsys.readouterr().out

    assert main(["approve", "--tier", "standard", "--project", str(project)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "run",
                "--tier",
                "standard",
                "--project",
                str(project),
                "--",
                *locked_command,
            ]
        )
        == 1
    )
    refused = capsys.readouterr()
    assert "backend_unavailable" in refused.err
    assert "blocked" not in refused.out

    assert (
        main(
            [
                "approve",
                "--tier",
                "resource-only",
                "--accept-weaker-isolation",
                "--project",
                str(project),
            ]
        )
        == 0
    )
    approval_id = capsys.readouterr().out.splitlines()[0].split()[-1]
    assert main(["policy", "--project", str(project)]) == 0
    assert json.loads(capsys.readouterr().out)["project_id"]
    assert main(["report", "--all", "--json", "--project", str(project)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "preflight.evidence-report"
    assert report["chain_verified"] is True
    assert report["record_count"] >= 5

    run_args = [
        "run",
        "--tier",
        "resource-only",
        "--project",
        str(project),
        "--",
        *locked_command,
    ]
    assert main(run_args) == 2
    assert "accept-weaker-isolation" in capsys.readouterr().err
    changed_command = [
        *run_args[:5],
        "--accept-weaker-isolation",
        "--",
        sys.executable,
        "-c",
        "print('different')",
    ]
    assert main(changed_command) == 2
    assert "differs from the approved entrypoint" in capsys.readouterr().err
    run_args.insert(5, "--accept-weaker-isolation")
    assert main(run_args) == 0
    assert "contained-contract" in capsys.readouterr().out

    moved = tmp_path / "source-moved"
    source.rename(moved)
    assert main(run_args) == 2
    assert "staged artifact is missing" in capsys.readouterr().err
    moved.rename(source)

    assert main(["revoke", approval_id, "--project", str(project)]) == 0
    assert "REVOKED" in capsys.readouterr().out
    assert main(["off", str(project)]) == 0
    assert "UNPROTECTED" in capsys.readouterr().out
    assert main(["status", str(project)]) == 1
    assert "UNPROTECTED" in capsys.readouterr().out


def test_cli_error_paths_fail_closed(
    tmp_path: Path,
    local_state: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert main(["off", str(project)]) == 2
    assert "no active or inactive" in capsys.readouterr().err
    assert main(["on", str(project)]) == 0
    capsys.readouterr()
    assert main(["approve", "--project", str(project)]) == 2
    assert "invalid dependency lock" in capsys.readouterr().err
    assert (
        main(
            [
                "install",
                "https://example.invalid/x",
                "--project",
                str(project),
                "--entrypoint",
                sys.executable,
            ]
        )
        == 2
    )
    assert "network acquisition is not available" in capsys.readouterr().err
    assert main(["report", "--project", str(project)]) == 0
    assert "verified evidence chain" in capsys.readouterr().out


def test_file_artifact_classification_and_rejections(tmp_path: Path) -> None:
    wheel = tmp_path / "demo.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
        archive.writestr("demo-1.0.dist-info/METADATA", "Name: demo\n")
        archive.writestr("demo-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
    assert identify_artifact(wheel).kind is ArtifactKind.WHEEL
    sdist = tmp_path / "demo.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        value = b"source"
        member = tarfile.TarInfo("demo/source.py")
        member.size = len(value)
        archive.addfile(member, io.BytesIO(value))
    assert identify_artifact(sdist).kind is ArtifactKind.SDIST
    zip_sdist = tmp_path / "demo.zip"
    with zipfile.ZipFile(zip_sdist, "w") as archive:
        archive.writestr("demo/source.py", "source")
    assert identify_artifact(zip_sdist).kind is ArtifactKind.SDIST
    unsupported = tmp_path / "demo.exe"
    unsupported.write_bytes(b"exe")
    with pytest.raises(ArtifactError, match="unsupported artifact type"):
        identify_artifact(unsupported)
    with pytest.raises(ArtifactError, match="does not exist"):
        identify_artifact(tmp_path / "missing.whl")


def test_archive_inspection_rejects_traversal_links_and_bombs(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.py", "bad")
    with pytest.raises(ArtifactError, match="escapes its root"):
        identify_artifact(traversal)

    linked = tmp_path / "linked.zip"
    with zipfile.ZipFile(linked, "w") as archive:
        member = zipfile.ZipInfo("demo/link")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "../outside")
    with pytest.raises(ArtifactError, match="symbolic link"):
        identify_artifact(linked)

    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("demo/zeros.bin", b"0" * (11 * 1024 * 1024))
    with pytest.raises(ArtifactError, match="unsafe expansion ratio"):
        identify_artifact(bomb)

    tar_bomb = tmp_path / "bomb.tar.gz"
    zeros = b"0" * (11 * 1024 * 1024)
    with tarfile.open(tar_bomb, "w:gz") as archive:
        member = tarfile.TarInfo("demo/zeros.bin")
        member.size = len(zeros)
        archive.addfile(member, io.BytesIO(zeros))
    with pytest.raises(ArtifactError, match="unsafe expansion ratio"):
        identify_artifact(tar_bomb)

    tar_link = tmp_path / "linked.tar.gz"
    with tarfile.open(tar_link, "w:gz") as archive:
        member = tarfile.TarInfo("demo/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside"
        archive.addfile(member)
    with pytest.raises(ArtifactError, match="link or special"):
        identify_artifact(tar_link)


def test_alpha_runner_contract_and_policy_inactive_paths(
    tmp_path: Path, local_state: Path
) -> None:
    backend = AlphaBackend()
    with pytest.raises(ValueError, match="does not provide"):
        backend.run(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            tier=IsolationTier.STANDARD,
            workload=CapabilitySet().workload,
        )
    with pytest.raises(ValueError, match="may not be empty"):
        backend.run(
            [],
            cwd=tmp_path,
            tier=IsolationTier.RESOURCE_ONLY,
            workload=CapabilitySet().workload,
        )
    result = backend.run(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        tier=IsolationTier.RESOURCE_ONLY,
        workload=CapabilitySet().workload,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
    assert not result.timed_out

    project = tmp_path / "project"
    project.mkdir()
    policy = activate_project(project)
    graph = _graph()
    grant_approval(policy, graph, tier=IsolationTier.RESOURCE_ONLY)
    inactive = policy.model_copy(update={"active": False})
    decision = evaluate(
        inactive,
        graph,
        _backend(IsolationTier.RESOURCE_ONLY),
        requested_tier=IsolationTier.RESOURCE_ONLY,
    )
    assert ReasonCode.PROJECT_INACTIVE in {reason.code for reason in decision.reasons}
