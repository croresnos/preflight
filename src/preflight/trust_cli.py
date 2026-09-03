"""CLI surface for the deterministic trust-platform alpha."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from preflight.artifacts import ArtifactError, identify_artifact
from preflight.backends import default_backend
from preflight.blast_chambers import doctor_status
from preflight.policy import evaluate
from preflight.project import (
    ProjectError,
    ProjectPolicy,
    activate_project,
    append_evidence,
    deactivate_project,
    find_project,
    grant_approval,
    read_evidence,
    read_lock,
    read_policy,
    revoke_approval,
    write_lock,
)
from preflight.trust import (
    DependencyGraph,
    IsolationTier,
    ReasonCode,
    trust_json_schema,
)


def _json(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, indent=2, sort_keys=True)


def _project(path: str) -> tuple[Path, ProjectPolicy]:
    root = find_project(path)
    if root is None:
        raise ProjectError(
            "UNPROTECTED: no preflight.toml found; run 'preflight on' first"
        )
    return root, read_policy(root)


def _on(args: argparse.Namespace) -> int:
    try:
        policy = activate_project(args.path)
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print(f"ACTIVE PROJECT  {Path(args.path).resolve()}")
    print(f"  project id  {policy.project_id}")
    print(f"  default     {policy.default_tier.value}")
    print("  policy      preflight.toml")
    print("  isolation   not implied; run 'preflight doctor'")
    return 0


def _off(args: argparse.Namespace) -> int:
    try:
        policy = deactivate_project(args.path)
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print("UNPROTECTED")
    print(f"  project id  {policy.project_id}")
    print("  Preflight will not describe ordinary commands as approved or isolated.")
    return 0


def _status(args: argparse.Namespace) -> int:
    root = find_project(args.path)
    if root is None:
        value: dict[str, object] = {
            "format": 1,
            "status": "unprotected",
            "root": str(Path(args.path).resolve()),
        }
        print(_json(value) if args.json else f"UNPROTECTED  {value['root']}")
        return 1
    try:
        policy = read_policy(root)
        evidence = read_evidence(policy)
        value = {
            "format": 1,
            "status": "active" if policy.active else "unprotected",
            "root": str(root),
            "project_id": policy.project_id,
            "policy_version": policy.policy_version,
            "default_tier": policy.default_tier.value,
            "evidence_records": len(evidence),
        }
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(_json(value))
    else:
        print(f"{str(value['status']).upper()}  {root}")
        print(f"  project id       {policy.project_id}")
        print(f"  policy version   {policy.policy_version}")
        print(f"  default tier     {policy.default_tier.value}")
        print(f"  evidence records {len(evidence)}")
    return 0 if policy.active else 1


def _doctor(args: argparse.Namespace) -> int:
    capabilities = default_backend().capabilities()
    if args.json:
        value = capabilities.model_dump(mode="json")
        value["blast_chambers"] = doctor_status()
        print(_json(value))
    else:
        print("preflight | backend capabilities")
        print(f"  backend    {capabilities.backend_id}")
        print(f"  platform   {capabilities.platform}")
        tiers = ", ".join(tier.value for tier in capabilities.available_tiers)
        print(f"  available  {tiers or '(none)'}")
        print("  standard   unavailable")
        print("  maximum    unavailable")
        for detail in capabilities.detail:
            print(f"  - {detail}")
        native = doctor_status()
        print(f"  blast chambers  {native['reason_code']}")
    return 0


def _schema(args: argparse.Namespace) -> int:
    print(_json(trust_json_schema()))
    return 0


def _install(args: argparse.Namespace) -> int:
    try:
        root, policy = _project(args.project)
        if not policy.active:
            raise ProjectError("UNPROTECTED: this project is deactivated")
        source = Path(args.source)
        if not source.exists():
            raise ProjectError(
                "network acquisition is not available until the brokered "
                "quarantine backend lands; pass a local directory, wheel, or sdist"
            )
        artifact = identify_artifact(source)
        entrypoint = tuple(args.entrypoint)
        if entrypoint and entrypoint[0] == "--":
            entrypoint = entrypoint[1:]
        if not entrypoint:
            raise ProjectError(
                "install requires --entrypoint followed by the exact argv to approve"
            )
        graph = DependencyGraph(root=artifact, entrypoint=entrypoint)
        write_lock(root, graph)
        append_evidence(
            policy,
            "artifact.staged",
            {
                "artifact": artifact.model_dump(mode="json"),
                "graph_sha256": graph.digest,
                "installed_on_host": False,
            },
        )
    except (ProjectError, ArtifactError) as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print("STAGED (NOT INSTALLED)  no candidate code was executed")
    print(f"  kind       {artifact.kind.value}")
    print(f"  sha256     {artifact.content_sha256}")
    print(f"  graph      {graph.digest}")
    print(f"  entrypoint {_json(list(graph.entrypoint))}")
    print("  identity   unsigned / provenance not verified")
    print(f"  next       preflight approve --tier {policy.default_tier.value}")
    return 1


def _approve(args: argparse.Namespace) -> int:
    try:
        root, policy = _project(args.project)
        if not policy.active:
            raise ProjectError("this project is deactivated")
        graph = read_lock(root)
        if not graph.entrypoint:
            raise ProjectError("the staged lock has no execution entrypoint")
        tier = IsolationTier(args.tier)
        if tier is IsolationTier.RESOURCE_ONLY and not args.accept_weaker_isolation:
            raise ProjectError(
                "resource-only does not enforce filesystem, network, credential, "
                "process, registry, device, or UI isolation; repeat with "
                "--accept-weaker-isolation to record that explicit downgrade"
            )
        grant = grant_approval(policy, graph, tier=tier)
    except (ProjectError, ValueError) as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print(f"APPROVED  {grant.approval_id}")
    print(f"  artifact  {grant.artifact_sha256}")
    print(f"  tier      {grant.tier.value}")
    print(f"  entrypoint {grant.entrypoint_sha256}")
    return 0


def _deny(args: argparse.Namespace) -> int:
    try:
        root, policy = _project(args.project)
        graph = read_lock(root)
        append_evidence(
            policy,
            "approval.denied",
            {
                "artifact_sha256": graph.root.content_sha256,
                "reason": args.reason or "user denied",
            },
        )
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print(f"DENIED  {graph.root.content_sha256}")
    return 0


def _revoke(args: argparse.Namespace) -> int:
    try:
        _, policy = _project(args.project)
        grant = revoke_approval(policy, args.approval_id)
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print(f"REVOKED  {grant.approval_id}")
    return 0


def _policy(args: argparse.Namespace) -> int:
    try:
        _, policy = _project(args.project)
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    print(_json(policy))
    return 0


def _report(args: argparse.Namespace) -> int:
    try:
        _, policy = _project(args.project)
        records = read_evidence(policy)
    except ProjectError as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    selected = records if args.all else records[-1:]
    if args.json:
        print(
            _json(
                {
                    "format": 1,
                    "schema": "preflight.evidence-report",
                    "chain_verified": True,
                    "record_count": len(records),
                    "records": [record.model_dump(mode="json") for record in selected],
                }
            )
        )
    else:
        print(f"preflight | verified evidence chain ({len(records)} records)")
        for record in selected:
            print(
                f"  {record.sequence:04d}  {record.event}  {record.recorded_at.isoformat()}"
            )
            print(f"        {record.record_sha256}")
    return 0


def _run(args: argparse.Namespace) -> int:
    try:
        root, policy = _project(args.project)
        graph = read_lock(root)
        tier = IsolationTier(args.tier or policy.default_tier)
        source = Path(graph.root.source)
        if not source.exists():
            append_evidence(
                policy,
                "run.refused",
                {"reason_code": ReasonCode.ARTIFACT_CHANGED.value},
            )
            raise ProjectError("staged artifact is missing; stage and review again")
        current = identify_artifact(source)
        if current.content_sha256 != graph.root.content_sha256:
            append_evidence(
                policy,
                "run.refused",
                {"reason_code": ReasonCode.ARTIFACT_CHANGED.value},
            )
            raise ProjectError(
                "artifact bytes changed after approval; stage and review again"
            )
        backend = default_backend()
        decision = evaluate(policy, graph, backend.capabilities(), requested_tier=tier)
        append_evidence(policy, "policy.decision", decision.model_dump(mode="json"))
        if not decision.allowed:
            print("REFUSED", file=sys.stderr)
            for reason in decision.reasons:
                print(f"  {reason.code.value}: {reason.message}", file=sys.stderr)
            return 1
        if tier is IsolationTier.RESOURCE_ONLY and not args.accept_weaker_isolation:
            raise ProjectError(
                "resource-only execution requires --accept-weaker-isolation on "
                "this run as well as on its approval"
            )
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        locked_command = list(graph.entrypoint)
        if command and command != locked_command:
            append_evidence(
                policy,
                "run.refused",
                {"reason_code": ReasonCode.ENTRYPOINT_CHANGED.value},
            )
            raise ProjectError(
                "run command differs from the approved entrypoint; stage and "
                "approve the new command first"
            )
        command = locked_command
        result = backend.run(
            command,
            cwd=root,
            tier=tier,
            workload=policy.capabilities.workload,
        )
        completed_evidence: dict[str, object] = {
            "tier": tier.value,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "elapsed_seconds": result.elapsed_seconds,
        }
        if result.native_evidence is not None:
            completed_evidence["blast_chambers"] = result.native_evidence
        append_evidence(policy, "run.completed", completed_evidence)
    except (ProjectError, ArtifactError, ValueError, OSError) as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


def add_trust_commands(commands: argparse._SubParsersAction) -> None:
    on = commands.add_parser("on", help="activate the trust policy for a project")
    on.add_argument("path", nargs="?", default=".")
    on.set_defaults(handler=_on)

    off = commands.add_parser("off", help="deactivate the project's trust policy")
    off.add_argument("path", nargs="?", default=".")
    off.set_defaults(handler=_off)

    status = commands.add_parser("status", help="show active or unprotected state")
    status.add_argument("path", nargs="?", default=".")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=_status)

    doctor = commands.add_parser("doctor", help="report enforceable isolation tiers")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=_doctor)

    schema = commands.add_parser(
        "schema", help="print the versioned trust-protocol JSON Schema bundle"
    )
    schema.set_defaults(handler=_schema)

    install = commands.add_parser(
        "install", help="stage and hash a local artifact without executing it"
    )
    install.add_argument("source")
    install.add_argument("--project", default=".")
    install.add_argument(
        "--entrypoint",
        nargs=argparse.REMAINDER,
        required=True,
        help="exact argv to bind into the lock; put this option last",
    )
    install.set_defaults(handler=_install)

    approve = commands.add_parser("approve", help="approve the exact staged artifact")
    approve.add_argument(
        "--tier",
        choices=[
            tier.value
            for tier in IsolationTier
            if tier is not IsolationTier.UNPROTECTED
        ],
        default=IsolationTier.STANDARD.value,
    )
    approve.add_argument("--project", default=".")
    approve.add_argument("--accept-weaker-isolation", action="store_true")
    approve.set_defaults(handler=_approve)

    deny = commands.add_parser("deny", help="record denial of the staged artifact")
    deny.add_argument("--reason")
    deny.add_argument("--project", default=".")
    deny.set_defaults(handler=_deny)

    revoke = commands.add_parser("revoke", help="revoke an artifact-bound approval")
    revoke.add_argument("approval_id")
    revoke.add_argument("--project", default=".")
    revoke.set_defaults(handler=_revoke)

    policy = commands.add_parser("policy", help="print the effective project policy")
    policy.add_argument("--project", default=".")
    policy.set_defaults(handler=_policy)

    report = commands.add_parser("report", help="verify and print audit evidence")
    report.add_argument("--project", default=".")
    report.add_argument("--json", action="store_true")
    report.add_argument("--all", action="store_true")
    report.set_defaults(handler=_report)

    run = commands.add_parser("run", help="run only after policy and tier approval")
    run.add_argument("--project", default=".")
    run.add_argument(
        "--tier",
        choices=[
            tier.value
            for tier in IsolationTier
            if tier is not IsolationTier.UNPROTECTED
        ],
    )
    run.add_argument("--accept-weaker-isolation", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(handler=_run)
