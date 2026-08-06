"""`preflight check` and `load_plugins` must reach the same verdict.

The command's whole claim is that it answers, without importing anything, the
question a host answers at startup. For two of the four preload checks it did
not: `check` judged the declared risks and the paperwork, and never looked at
`supported_platforms` or at the release ring. A package the gate would refuse
printed "Paperwork is consistent" and exited `0`.

That is worse than a missing feature. The manual recommends putting
`preflight check` in CI *specifically* so a plugin that would be refused at
startup is caught at review time instead, and for half the checks the command
was quietly answering a smaller question than the one being asked of it.

Both paths now call `preflight.registry.preload_refusals`. These tests pin the
consequence rather than the refactor: the same package, judged twice, must come
back with the same answer in the same words. Rewording a refusal in the registry
and forgetting the command is exactly the drift this file exists to catch, and
matching the strings is what catches it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from preflight import load_plugins
from preflight.cli import main
from preflight.inspect import inspect_package
from preflight.manifest import Platform
from preflight.registry import host_platform

from test_inspect import _manifest, _write_package  # noqa: E402


def _other_platform() -> Platform:
    """A platform this test run is definitely not on."""
    running = host_platform()
    return Platform.LINUX if running is not Platform.LINUX else Platform.WINDOWS


def _package(root: Path, name: str, **manifest_changes) -> Path:
    """One plugin package on disk, with its manifest tweaked at the top level.

    The plugin it writes really does satisfy the ABI. That matters for the
    negative test below: the shared helper's stub returns ``None``, which the
    gate refuses *after* importing it, on a check `check` cannot make and does
    not claim to. Comparing the two paths needs a package whose only possible
    refusal is one they both get to see.
    """
    manifest = _manifest(
        package_id=f"example.{name}",
        plugin_id=name,
        entrypoint=f"{name}.plugin:create_plugin",
    )
    plugin_changes = manifest_changes.pop("plugin", {})
    manifest.update(manifest_changes)
    manifest["plugin"].update(plugin_changes)
    folder = _write_package(root, name, manifest=manifest)
    folder.joinpath("plugin.py").write_text(
        "from preflight import PluginManifest\n"
        f"_MANIFEST = PluginManifest.model_validate({manifest['plugin']!r})\n"
        "class Widget:\n"
        "    @property\n"
        "    def manifest(self):\n"
        "        return _MANIFEST\n"
        "def create_plugin():\n"
        "    return Widget()\n",
        encoding="utf-8",
    )
    return folder


def _gate_refusal(root: Path, package_id: str, folder: str) -> str | None:
    """What `load_plugins` says about one package, or ``None`` if it loaded."""
    sys.path.insert(0, str(root))
    try:
        report = load_plugins(root, allow=[package_id])
    finally:
        sys.path.remove(str(root))
    outcome = next(item for item in report.outcomes if item.folder == folder)
    return None if outcome.loaded else outcome.reason


@pytest.mark.parametrize(
    "name, changes",
    [
        ("wrongplatform", {"plugin": {"supported_platforms": [_other_platform().value]}}),
        ("experimental", {"release_ring": "experimental"}),
        ("internalonly", {"visibility": "internal", "release_ring": "beta"}),
    ],
)
def test_check_refuses_what_the_gate_refuses_and_says_the_same_thing(
    tmp_path, monkeypatch, capsys, name, changes
):
    """Three packages the gate turns away that `check` used to pass.

    Each one is well-formed: the manifest parses, the entrypoint resolves, and
    no tool declares a risk anybody refused. The only thing wrong with them is
    that this build will not take them -- which is precisely what a command
    claiming to predict the gate has to notice.
    """
    _package(tmp_path, name, **changes)
    monkeypatch.chdir(tmp_path)

    assert main(["check", name]) == 1
    printed = capsys.readouterr().out

    from_the_gate = _gate_refusal(tmp_path, f"example.{name}", name)
    assert from_the_gate is not None, "the gate should have refused this"
    assert from_the_gate in printed, (
        f"check must quote the gate verbatim.\n"
        f"gate said: {from_the_gate!r}\n"
        f"check printed:\n{printed}"
    )


def test_check_still_passes_a_package_this_build_would_load(tmp_path, monkeypatch):
    """The negative half. A widened check that refuses everything proves nothing."""
    _package(tmp_path, "fine")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "fine"]) == 0
    assert _gate_refusal(tmp_path, "example.fine", "fine") is None


def test_a_platform_the_host_does_support_is_not_a_refusal(tmp_path, monkeypatch):
    """`supported_platforms` naming this OS must not be read as a restriction."""
    _package(tmp_path, "supported", plugin={"supported_platforms": [host_platform().value]})
    monkeypatch.chdir(tmp_path)

    assert main(["check", "supported"]) == 0


def test_the_saved_edition_is_what_check_judges_against(tmp_path, monkeypatch):
    """A settings file that widens the edition must widen `check` too.

    `preflight settings` prints `edition` as being in force. If the command that
    consults settings ignored it, the display would be stating something untrue
    about the run the reader is about to make.
    """
    _package(tmp_path, "experimental", release_ring="experimental")
    (tmp_path / "preflight.settings.json").write_text(
        json.dumps({"version": 1, "edition": "development"}), encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")  # a project root
    monkeypatch.chdir(tmp_path)

    assert main(["check", "experimental"]) == 0, (
        "a development build accepts the experimental ring, and the settings "
        "file said this is one"
    )


def test_inspecting_a_refused_package_still_does_not_import_it(tmp_path):
    """The new checks must not have cost the command its one hard guarantee.

    `_write_package` plants a tripwire in each package body. Deciding that a
    package is refused for its platform is a decision made from parsed JSON, and
    it must stay one.
    """
    _package(tmp_path, "wrongplatform", plugin={"supported_platforms": [_other_platform().value]})

    inspection = inspect_package(tmp_path / "wrongplatform")

    assert inspection.refusals(), "expected a platform refusal"
    assert not list(tmp_path.glob("*ran*")), "inspecting must not execute the package"
    assert "wrongplatform" not in sys.modules
