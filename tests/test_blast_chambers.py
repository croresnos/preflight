from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from preflight import backends, blast_chambers
from preflight.trust import IsolationTier, WorkloadProfile


def test_missing_installed_client_is_reported_without_fallback(
    monkeypatch, tmp_path: Path
) -> None:
    missing = tmp_path / "missing-client.exe"
    monkeypatch.setattr(blast_chambers, "configured_client", lambda: missing)

    status = blast_chambers.doctor_status()

    assert status["reason_code"] == "client_missing"
    assert status["verified_identity"] is False
    assert not any(status["achieved_resource_controls"].values())


def test_probe_requires_identity_and_every_resource_control(
    monkeypatch, tmp_path: Path
) -> None:
    client = tmp_path / "client.exe"
    client.touch()
    monkeypatch.setattr(blast_chambers, "configured_client", lambda: client)
    controls = {
        name: True
        for name in blast_chambers._REQUIRED_CONTROLS  # noqa: SLF001
    }
    response = {
        "service_version": "1.0.0",
        "protocol_version": 1,
        "service_pid": 42,
        "identity_verified": True,
        "controls": controls,
        "missing_protections": [
            "filesystem",
            "registry",
            "credentials",
            "network",
            "ui_devices",
            "same_user_brokers",
        ],
        "reason_code": "available",
    }
    completed = subprocess.CompletedProcess(
        [], 0, stdout=__import__("json").dumps(response)
    )
    monkeypatch.setattr(
        blast_chambers.subprocess, "run", lambda *args, **kwargs: completed
    )

    status = blast_chambers.doctor_status()

    assert status["reason_code"] == "available"
    controls["caller_token"] = False
    completed.stdout = __import__("json").dumps(response)
    assert blast_chambers.doctor_status()["reason_code"] == "backend_unavailable"


def test_configured_native_client_never_falls_back(monkeypatch, tmp_path: Path) -> None:
    client = tmp_path / "client.exe"
    client.touch()
    monkeypatch.setattr(backends.sys, "platform", "win32")
    monkeypatch.setattr(backends, "configured_client", lambda: client)
    monkeypatch.setattr(
        backends,
        "doctor_status",
        lambda: {"reason_code": "backend_unavailable"},
    )

    backend = backends.default_backend()

    assert isinstance(backend, backends.BlastChambersBackend)
    assert backend.capabilities().available_tiers == ()


def test_windows_without_native_client_never_falls_back(monkeypatch) -> None:
    monkeypatch.setattr(backends.sys, "platform", "win32")
    monkeypatch.setattr(backends, "configured_client", lambda: None)
    monkeypatch.setattr(
        backends,
        "doctor_status",
        lambda: {"reason_code": "not_installed"},
    )

    backend = backends.default_backend()

    assert isinstance(backend, backends.BlastChambersBackend)
    assert backend.capabilities().available_tiers == ()


def test_proven_native_response_maps_to_run_result(monkeypatch, tmp_path: Path) -> None:
    client = tmp_path / "client.exe"
    client.touch()
    monkeypatch.setattr(backends, "configured_client", lambda: client)
    monkeypatch.setattr(
        backends,
        "doctor_status",
        lambda: {"reason_code": "available"},
    )
    evidence = {
        "payload_sha256": "a" * 64,
        "previous_sha256": "b" * 64,
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature": "MEUCIQexample",
        "sealed": True,
    }
    response = {
        "returncode": 7,
        "stdout": "bounded output",
        "stderr": "",
        "elapsed_ms": 125,
        "timed_out": False,
        "evidence": evidence,
    }
    completed = subprocess.CompletedProcess(
        [], 0, stdout=__import__("json").dumps(response), stderr=""
    )
    monkeypatch.setattr(backends.subprocess, "run", lambda *args, **kwargs: completed)
    backend = backends.BlastChambersBackend()

    capabilities = backend.capabilities()
    result = backend.run(
        ["fixture.exe"],
        cwd=tmp_path,
        tier=IsolationTier.RESOURCE_ONLY,
        workload=WorkloadProfile.STANDARD,
    )

    assert capabilities.available_tiers == (IsolationTier.RESOURCE_ONLY,)
    assert capabilities.resource_limits is True
    assert result.returncode == 7
    assert result.elapsed_seconds == 0.125
    assert result.native_evidence == evidence


def test_client_discovery_has_no_untrusted_path_fallback(
    monkeypatch, tmp_path: Path
) -> None:
    fake = tmp_path / "fake-client.exe"
    fake.touch()
    monkeypatch.setenv("PREFLIGHT_BLAST_CHAMBERS_CLIENT", str(fake))
    monkeypatch.setattr(blast_chambers.sys, "platform", "linux")
    assert blast_chambers.configured_client() is None
    monkeypatch.setattr(blast_chambers.sys, "platform", "win32")
    monkeypatch.setattr(blast_chambers, "_program_files_directory", lambda: None)
    assert blast_chambers.configured_client() is None


def test_client_discovery_uses_only_machine_install_root(
    monkeypatch, tmp_path: Path
) -> None:
    client = tmp_path / "Preflight" / "Blast Chambers" / "blast-chambers-client.exe"
    client.parent.mkdir(parents=True)
    client.touch()
    monkeypatch.setattr(
        blast_chambers,
        "_program_files_directory",
        lambda: tmp_path,
    )

    assert blast_chambers.configured_client() == client


def test_machine_install_root_fails_closed_on_registry_error(monkeypatch) -> None:
    def refuse_registry_access(*args, **kwargs):
        raise OSError("registry unavailable")

    fake_winreg = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        KEY_READ=1,
        KEY_WOW64_64KEY=2,
        OpenKey=refuse_registry_access,
    )
    monkeypatch.setattr(blast_chambers.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)

    assert blast_chambers._program_files_directory() is None  # noqa: SLF001


@pytest.mark.parametrize(
    ("completed", "reason"),
    [
        (
            subprocess.CompletedProcess([], 78, stdout="", stderr="refused"),
            "backend_unavailable",
        ),
        (subprocess.CompletedProcess([], 0, stdout="{", stderr=""), "invalid_response"),
        (
            subprocess.CompletedProcess([], 0, stdout="[]", stderr=""),
            "invalid_response",
        ),
        (
            subprocess.CompletedProcess([], 0, stdout='{"unexpected":true}', stderr=""),
            "invalid_response",
        ),
    ],
)
def test_doctor_probe_rejects_untrusted_responses(
    monkeypatch, tmp_path: Path, completed, reason: str
) -> None:
    client = tmp_path / "client.exe"
    client.touch()
    monkeypatch.setattr(blast_chambers, "configured_client", lambda: client)
    monkeypatch.setattr(
        blast_chambers.subprocess, "run", lambda *args, **kwargs: completed
    )
    assert blast_chambers.doctor_status()["reason_code"] == reason


def test_native_runner_rejects_invalid_requests_before_launch(tmp_path: Path) -> None:
    backend = backends.BlastChambersBackend()
    with pytest.raises(ValueError, match="standard"):
        backend.run(
            ["fixture.exe"],
            cwd=tmp_path,
            tier=IsolationTier.STANDARD,
            workload=WorkloadProfile.STANDARD,
        )
    with pytest.raises(ValueError, match="empty"):
        backend.run(
            [],
            cwd=tmp_path,
            tier=IsolationTier.RESOURCE_ONLY,
            workload=WorkloadProfile.STANDARD,
        )


def test_legacy_windows_timeout_falls_back_to_direct_kill(monkeypatch) -> None:
    class FakeProcess:
        pid = 123
        killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

    process = FakeProcess()

    def failed_taskkill(*args, **kwargs):
        raise OSError("taskkill unavailable")

    monkeypatch.setattr(backends.subprocess, "run", failed_taskkill)
    backends._terminate_windows_tree(process)  # type: ignore[arg-type]  # noqa: SLF001
    assert process.killed is True
