"""Backend capability reporting and an explicitly limited alpha runner."""

from __future__ import annotations

import ctypes
import os

# This module is the explicit, policy-gated process launcher.
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from preflight.trust import BackendCapabilities, IsolationTier, WorkloadProfile


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool = False


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
            version = sys.getwindowsversion()
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
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
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
            process.kill()
            stdout, stderr = process.communicate()
        return RunResult(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed_seconds=time.monotonic() - started,
            timed_out=timed_out,
        )


def default_backend() -> IsolationBackend:
    return AlphaBackend()
