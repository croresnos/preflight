"""Fail-closed discovery for the separately installed Windows service client."""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

_REQUIRED_CONTROLS = (
    "suspended_before_assignment",
    "kill_on_job_close",
    "active_process_limit",
    "process_memory_limit",
    "job_memory_limit",
    "cpu_hard_cap",
    "cpu_time_limit",
    "wall_clock_limit",
    "output_limit",
    "no_breakaway",
    "caller_token",
)
_MISSING_PROTECTIONS = (
    "filesystem",
    "registry",
    "credentials",
    "network",
    "ui_devices",
    "same_user_brokers",
)
_DOCTOR_FIELDS = {
    "service_version",
    "protocol_version",
    "service_pid",
    "identity_verified",
    "controls",
    "missing_protections",
    "reason_code",
}


def _program_files_directory() -> Path | None:
    """Read the machine-wide install root from protected registry state."""
    if sys.platform != "win32":
        return None
    try:
        import winreg

        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            access=access,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "ProgramFilesDir")
    except (ImportError, OSError):
        return None
    if value_type != winreg.REG_SZ or not isinstance(value, str) or not value:
        return None
    return Path(value).resolve()


def configured_client() -> Path | None:
    """Return only the administrator-installed client path."""
    program_files = _program_files_directory()
    if program_files is None:
        return None
    candidate = (
        program_files / "Preflight" / "Blast Chambers" / "blast-chambers-client.exe"
    )
    return candidate if candidate.is_file() else None


def doctor_status() -> dict[str, Any]:
    """Probe without inferring enforcement from available Win32 primitives."""
    client = configured_client()
    base: dict[str, Any] = {
        "service_version": None,
        "protocol_version": 1,
        "verified_identity": False,
        "achieved_resource_controls": {
            control: False for control in _REQUIRED_CONTROLS
        },
        "missing_protections": list(_MISSING_PROTECTIONS),
        "reason_code": "not_installed",
    }
    if client is None:
        return base
    base["client_path"] = str(client)
    if not client.is_file():
        base["reason_code"] = "client_missing"
        return base
    try:
        completed = subprocess.run(  # nosec B603
            [str(client), "doctor", "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
        )
    except (OSError, subprocess.SubprocessError):
        base["reason_code"] = "probe_failed"
        return base
    if completed.returncode != 0:
        base["reason_code"] = "backend_unavailable"
        return base
    try:
        response = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        base["reason_code"] = "invalid_response"
        return base
    if not isinstance(response, dict):
        base["reason_code"] = "invalid_response"
        return base
    if set(response) != _DOCTOR_FIELDS:
        base["reason_code"] = "invalid_response"
        return base
    controls = response.get("controls")
    if not isinstance(controls, dict) or set(controls) != set(_REQUIRED_CONTROLS):
        base["reason_code"] = "invalid_response"
        return base
    reason_code = response.get("reason_code")
    if not isinstance(reason_code, str):
        base["reason_code"] = "invalid_response"
        return base
    exact_controls = {
        control: controls.get(control) is True for control in _REQUIRED_CONTROLS
    }
    base.update(
        {
            "service_version": response.get("service_version"),
            "protocol_version": response.get("protocol_version"),
            "service_pid": response.get("service_pid"),
            "verified_identity": response.get("identity_verified") is True,
            "achieved_resource_controls": exact_controls,
            "reason_code": reason_code,
        }
    )
    if (
        type(base["protocol_version"]) is not int
        or base["protocol_version"] != 1
        or type(base["service_pid"]) is not int
        or base["service_pid"] <= 0
        or not isinstance(base["service_version"], str)
        or not base["service_version"]
        or not base["verified_identity"]
        or not all(exact_controls.values())
        or response.get("missing_protections") != list(_MISSING_PROTECTIONS)
        or base["reason_code"] != "available"
    ):
        base["reason_code"] = "backend_unavailable"
    return base
