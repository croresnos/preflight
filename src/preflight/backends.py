"""Backend capability reporting and an explicitly limited alpha runner."""

from __future__ import annotations

import ctypes
import json
import os
import signal

# This module is the explicit, policy-gated process launcher.
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from preflight.blast_chambers import configured_client, doctor_status
from preflight.trust import BackendCapabilities, IsolationTier, WorkloadProfile


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool = False
    native_evidence: dict[str, object] | None = None


class IsolationBackend(Protocol):
    def capabilities(self) -> BackendCapabilities: ...

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        tier: IsolationTier,
        workload: WorkloadProfile,
    ) -> RunResult: ...


def _clean_environment() -> dict[str, str]:
    """A minimal environment with no inherited application credentials."""
    keep = {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in keep}


def _windows_primitive_diagnostics() -> tuple[str, ...]:
    """Feature-detect primitives without treating detection as enforcement."""

    def exports(library: str, *names: str) -> bool:
        try:
            loader = getattr(ctypes, "WinDLL")
            dll = loader(library, use_last_error=True)
        except (AttributeError, OSError):
            return False
        return all(hasattr(dll, name) for name in names)

    job_objects = exports(
        "kernel32.dll",
        "CreateJobObjectW",
        "SetInformationJobObject",
        "AssignProcessToJobObject",
        "TerminateJobObject",
    )
    app_container = exports(
        "userenv.dll",
        "CreateAppContainerProfile",
        "DeriveAppContainerSidFromAppContainerName",
    )
    sandbox_api = exports("advapi32.dll", "CreateProcessInSandbox")
    return (
        f"Job Object primitives detected: {str(job_objects).lower()}",
        f"AppContainer profile primitives detected: {str(app_container).lower()}",
        f"experimental sandbox process API detected: {str(sandbox_api).lower()}",
        "primitive detection is diagnostic only; no native broker is active",
        "Hyper-V availability requires the future privileged service probe",
    )


def _terminate_windows_tree(process: subprocess.Popen[str]) -> None:
    """Best-effort legacy cleanup; never treated as a containment guarantee."""
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    taskkill = Path(system_root) / "System32" / "taskkill.exe"
    try:
        subprocess.run(  # nosec B603
            [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    if process.poll() is None:
        process.kill()


class AlphaBackend:
    """Resource/time containment only; not a security sandbox.

    Standard and maximum are deliberately absent from the capability set. This
    backend exists to exercise the approval, evidence, timeout, and downgrade
    contracts before the native AppContainer and Hyper-V service lands.
    """

    backend_id = "alpha-resource-runner/1"

    def capabilities(self) -> BackendCapabilities:
        windows = sys.platform == "win32"
        detail = [
            "resource-only enforces a wall-clock timeout only",
            "resource-only does not enforce filesystem or network policy",
            "resource-only does not isolate credentials, devices, registry, or UI",
            "standard requires the future native AppContainer service",
            "maximum requires the future Hyper-V quarantine service",
        ]
        if windows:
            get_windows_version = getattr(sys, "getwindowsversion")
            version = get_windows_version()
            detail.insert(0, f"Windows build {version.build}")
            detail[1:1] = _windows_primitive_diagnostics()
            if version.build < 22000:
                detail.insert(1, "unsupported Windows build: Windows 11 is required")
        else:
            detail.insert(0, f"unsupported alpha host platform: {sys.platform}")
        return BackendCapabilities(
            backend_id=self.backend_id,
            platform=sys.platform,
            available_tiers=(IsolationTier.RESOURCE_ONLY,),
            filesystem_enforced=False,
            network_enforced=False,
            credential_isolation=False,
            process_isolation=False,
            resource_limits=False,
            independent_kernel=False,
            detail=tuple(detail),
        )

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        tier: IsolationTier,
        workload: WorkloadProfile,
    ) -> RunResult:
        if tier is not IsolationTier.RESOURCE_ONLY:
            raise ValueError(f"backend does not provide isolation tier '{tier.value}'")
        if not command:
            raise ValueError("run command may not be empty")
        timeout = 30 if workload is WorkloadProfile.STANDARD else 300
        started = time.monotonic()
        flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if sys.platform == "win32"
            else 0
        )
        # Executing the approved argv is this backend's purpose. It is passed as
        # a list with shell=False; policy and isolation decisions happen first.
        process = subprocess.Popen(  # nosec B603
            command,
            cwd=cwd,
            env=_clean_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=flags,
            start_new_session=sys.platform != "win32",
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            if sys.platform == "win32":
                # Close obvious descendants without claiming a race-free
                # boundary. Blast Chambers replaces this with kill-on-close.
                _terminate_windows_tree(process)
            else:
                # start_new_session=True above made the workload its own process
                # group. Kill that complete group so timeout does not strand
                # descendants on POSIX hosts.
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        return RunResult(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed_seconds=time.monotonic() - started,
            timed_out=timed_out,
        )


class BlastChambersBackend:
    """Dormant-until-proven adapter for the separately installed native client."""

    backend_id = "blast-chambers/resource-only-v1"

    def capabilities(self) -> BackendCapabilities:
        status = doctor_status()
        available = status["reason_code"] == "available"
        detail = [
            f"native service status: {status['reason_code']}",
            "resource-only does not enforce filesystem, registry, or network policy",
            "resource-only does not isolate credentials, UI, devices, or brokers",
            "standard and maximum remain unavailable",
        ]
        return BackendCapabilities(
            backend_id=self.backend_id,
            platform=sys.platform,
            available_tiers=(IsolationTier.RESOURCE_ONLY,) if available else (),
            filesystem_enforced=False,
            network_enforced=False,
            credential_isolation=False,
            process_isolation=False,
            resource_limits=available,
            independent_kernel=False,
            detail=tuple(detail),
        )

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        tier: IsolationTier,
        workload: WorkloadProfile,
    ) -> RunResult:
        if tier is not IsolationTier.RESOURCE_ONLY:
            raise ValueError(f"backend does not provide isolation tier '{tier.value}'")
        if not command:
            raise ValueError("run command may not be empty")
        client = configured_client()
        status = doctor_status()
        if (
            client is None
            or not client.is_file()
            or status["reason_code"] != "available"
        ):
            raise OSError(
                "backend_unavailable: Blast Chambers identity or controls failed"
            )
        wall_time_ms = 30_000 if workload is WorkloadProfile.STANDARD else 300_000
        request = {
            "command": command,
            "cwd": str(cwd.resolve()),
            "limits": {
                "wall_time_ms": wall_time_ms,
                "cpu_time_ms": wall_time_ms,
                "cpu_rate_percent": 100,
                "process_memory_bytes": 512 * 1024 * 1024,
                "job_memory_bytes": (
                    1024 * 1024 * 1024
                    if workload is WorkloadProfile.STANDARD
                    else 4 * 1024 * 1024 * 1024
                ),
                "active_process_limit": (
                    16 if workload is WorkloadProfile.STANDARD else 64
                ),
                "output_bytes": 16 * 1024 * 1024,
            },
        }
        completed = subprocess.run(  # nosec B603
            [str(client), "run", "--json"],
            input=json.dumps(request, sort_keys=True, separators=(",", ":")),
            capture_output=True,
            text=True,
            check=False,
            timeout=(wall_time_ms / 1000) + 15,
            env=_clean_environment(),
        )
        if completed.returncode != 0:
            raise OSError(
                "backend_unavailable: Blast Chambers refused the request: "
                + completed.stderr.strip()
            )
        try:
            response = json.loads(completed.stdout)
            if not isinstance(response, dict) or set(response) != {
                "returncode",
                "stdout",
                "stderr",
                "elapsed_ms",
                "timed_out",
                "evidence",
            }:
                raise ValueError("native response schema mismatch")
            if (
                type(response["returncode"]) is not int
                or not isinstance(response["stdout"], str)
                or not isinstance(response["stderr"], str)
                or type(response["elapsed_ms"]) is not int
                or response["elapsed_ms"] < 0
                or not isinstance(response["timed_out"], bool)
            ):
                raise ValueError("native response types are invalid")
            returncode = response["returncode"]
            stdout = response["stdout"]
            stderr = response["stderr"]
            elapsed_ms = response["elapsed_ms"]
            timed_out = response["timed_out"]
            evidence = response["evidence"]
            if not isinstance(evidence, dict) or set(evidence) != {
                "payload_sha256",
                "previous_sha256",
                "signature_algorithm",
                "signature",
                "sealed",
            }:
                raise ValueError("native evidence schema mismatch")
            hashes = (evidence["payload_sha256"], evidence["previous_sha256"])
            if not all(
                isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for value in hashes
            ):
                raise ValueError("native evidence hash is invalid")
            if (
                evidence["signature_algorithm"] != "ECDSA_P256_SHA256"
                or not isinstance(evidence["signature"], str)
                or not evidence["signature"]
                or evidence.get("sealed") is not True
            ):
                raise ValueError("native evidence was not sealed")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise OSError(
                "backend_unavailable: invalid Blast Chambers response"
            ) from exc
        return RunResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed_seconds=elapsed_ms / 1000,
            timed_out=timed_out,
            native_evidence=dict(evidence),
        )


def default_backend() -> IsolationBackend:
    if sys.platform == "win32":
        # Windows resource-only is a native Job Object boundary or it is
        # unavailable. Service/client absence and every discovery failure stay
        # on this path; never downgrade to the legacy Python runner.
        return BlastChambersBackend()
    return AlphaBackend()
