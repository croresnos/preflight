"""A manifest may name a module and no attribute. What that costs, and what it does not.

An entrypoint with a colon says *ask the package what it is, and check the answer
against this file*. An entrypoint without one says *this file is the whole
description*, and preflight adapts the module using it. The second shape exists
for the case the first cannot serve: a package that has never heard of preflight
was never going to return a ``PluginManifest``.

The waiver is the point of this file. One check -- the runtime manifest equalling
the declared one -- is not made for a bare entrypoint, and the tests here say so
in both directions: that everything else still is, and that nothing pretends the
waived one passed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from preflight import load_plugins
from preflight.manifest import PluginPackageManifest

TRIPWIRE = "tripwire.log"


def _manifest(*, entrypoint: str, plugin_id: str = "notepad") -> dict:
    return {
        "schema_version": "1.0",
        "package_id": f"local.{plugin_id}",
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": entrypoint,
        "plugin": {
            "schema_version": "1.0",
            "plugin_id": plugin_id,
            "name": "Notepad",
            "module_version": "0.1.0",
            "tools": [{"name": "notepad.jot", "risk": "write"}],
        },
    }


def _unaware_package(root: Path, name: str = "notepad", *, body: str = "") -> Path:
    """A package that does not import preflight and has no ``create_plugin``."""
    plugins = root / "plugins"
    folder = plugins / name
    folder.mkdir(parents=True)
    folder.joinpath("__init__.py").write_text(
        body or "def jot(text):\n    return f'noted: {text}'\n", encoding="utf-8"
    )
    return plugins


@pytest.fixture
def importable(monkeypatch):
    """Put a plugin root on ``sys.path`` and take the modules back off after.

    The gate requires the host to have done this -- preflight never touches
    ``sys.path`` itself -- and a module left in ``sys.modules`` would be found by
    the next test rather than loaded from its own directory.
    """

    def use(plugins: Path) -> Path:
        monkeypatch.syspath_prepend(str(plugins))
        return plugins

    before = set(sys.modules)
    yield use
    for name in set(sys.modules) - before:
        del sys.modules[name]


def test_a_package_that_never_heard_of_preflight_loads_from_a_bare_entrypoint(
    tmp_path, importable
):
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert [outcome.folder for outcome in report.refused] == []
    plugin = report.get("notepad")
    assert plugin is not None
    # Delegation, so a host calls the package's own functions through the object
    # preflight handed back rather than importing the module a second time.
    assert plugin.jot("milk") == "noted: milk"
    assert plugin.manifest.plugin_id == "notepad"


def test_the_adapted_module_is_not_modified_by_being_adapted(tmp_path, importable):
    """The wrapper carries the manifest. The module must come out as it went in.

    Setting ``manifest`` on the module would be shorter and would leave a
    preflight-shaped mark on a package whose whole premise is that it has none --
    visible to every other importer of it, and to its own code.
    """
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad")), encoding="utf-8"
    )

    load_plugins(plugins, allow=["local.notepad"])

    assert not hasattr(sys.modules["notepad"], "manifest")


def test_the_report_says_a_bare_entrypoint_was_adapted(tmp_path, importable):
    """`LOADED` must not quietly mean two different strengths of the same word."""
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert report.loaded[0].self_reported is False
    assert "manifest not self-reported" in report.text()


def test_a_colon_entrypoint_is_still_checked_against_what_the_package_reports(
    tmp_path, importable
):
    """The waiver is for bare entrypoints only, and this is the proof.

    Same package, same manifest, one colon. The plugin reports a version its
    manifest does not declare, and that has to still be a refusal -- otherwise
    the bare form did not waive a check, it removed one.
    """
    plugins = _unaware_package(
        tmp_path,
        body=(
            "from preflight import PluginManifest\n"
            "class Notepad:\n"
            "    @property\n"
            "    def manifest(self):\n"
            "        return PluginManifest.model_validate({\n"
            "            'plugin_id': 'notepad',\n"
            "            'name': 'Notepad',\n"
            "            'module_version': '9.9.9',\n"
            "            'tools': [{'name': 'notepad.jot', 'risk': 'write'}],\n"
            "        })\n"
            "def create_plugin():\n"
            "    return Notepad()\n"
        ),
    )
    importable(plugins)
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad:create_plugin")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert len(report.refused) == 1
    assert "does not match" in report.refused[0].reason
    assert "9.9.9" in report.refused[0].reason


def test_a_bare_entrypoint_is_still_confined_to_the_trusted_root(tmp_path, importable):
    """Waiving one check does not widen the boundary. This is the boundary.

    ``json`` is a module every interpreter can import and no plugin root
    contains. Without the colon there is no attribute to fail on, so if the
    confinement check were skipped alongside the manifest comparison this would
    load the standard library and report it as a plugin.
    """
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="json")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert len(report.refused) == 1
    assert "outside the trusted plugin root" in report.refused[0].reason
    assert report.refused[0].code_ran is False


def test_the_tool_surface_comes_from_the_file_either_way(tmp_path, importable):
    """A bare entrypoint cannot widen what the host advertises.

    The registry reads the declared tools out of the manifest, never out of the
    instance, so the adapted module has no way to add one. Said out loud here
    because it is the reason the waiver is affordable.
    """
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert report.registry.tool_owner("notepad.jot") == "notepad"
    assert report.registry.tool_owner("notepad.anything_else") is None


@pytest.mark.parametrize(
    "entrypoint, expected",
    [
        ("notepad.plugin:create_plugin", True),
        ("notepad:create_plugin", True),
        ("notepad", False),
        ("notepad.plugin", False),
    ],
)
def test_the_colon_is_what_says_whether_the_package_reports_its_own_manifest(
    entrypoint, expected
):
    package = PluginPackageManifest.model_validate(_manifest(entrypoint=entrypoint))

    assert package.self_reports_manifest is expected


def test_a_bare_entrypoint_naming_a_module_that_is_not_there_is_still_refused(
    tmp_path, importable
):
    plugins = importable(_unaware_package(tmp_path))
    (plugins / "notepad" / "manifest.json").write_text(
        json.dumps(_manifest(entrypoint="notepad.missing")), encoding="utf-8"
    )

    report = load_plugins(plugins, allow=["local.notepad"])

    assert len(report.refused) == 1
    assert "has no file on disk" in report.refused[0].reason
