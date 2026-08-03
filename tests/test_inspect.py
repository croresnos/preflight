"""``preflight check`` reads a package without running it.

The assertion that matters in this file is
``test_inspecting_a_package_never_imports_it``. Every other test here says the
inspector reported the right thing; that one says it reported it without giving
the package a turn, which is the only reason inspection is safe to point at code
you have not read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from preflight.inspect import inspect_directory, inspect_package

TRIPWIRE = "tripwire.log"


def _manifest(
    *,
    package_id: str = "example.widget",
    plugin_id: str = "widget",
    entrypoint: str = "widget.plugin:create_plugin",
    tools: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "1.0",
        "package_id": package_id,
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": entrypoint,
        "plugin": {
            "schema_version": "1.0",
            "plugin_id": plugin_id,
            "name": "Widget",
            "module_version": "1.0.0",
            "tools": tools if tools is not None else [],
        },
    }


def _write_package(
    root: Path,
    name: str,
    *,
    manifest: dict | None = None,
    manifest_text: str | None = None,
    package: bool = True,
    module: bool = True,
) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    if package:
        # A tripwire in the package body. If anything imports this, it says so.
        folder.joinpath("__init__.py").write_text(
            f"from pathlib import Path\n"
            f"Path({str(root / TRIPWIRE)!r}).write_text('{name} ran')\n",
            encoding="utf-8",
        )
    if module:
        folder.joinpath("plugin.py").write_text(
            "def create_plugin():\n    return None\n", encoding="utf-8"
        )
    if manifest_text is not None:
        folder.joinpath("manifest.json").write_text(manifest_text, encoding="utf-8")
    elif manifest is not None:
        folder.joinpath("manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
    return folder


def test_inspecting_a_package_never_imports_it(tmp_path: Path, monkeypatch):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())
    # Make it genuinely importable, so nothing but the inspector's own restraint
    # is stopping the import. A test where the import could not have worked
    # anyway proves nothing.
    monkeypatch.syspath_prepend(str(tmp_path))

    inspection = inspect_package(folder)

    assert inspection.consistent
    assert not (tmp_path / TRIPWIRE).exists()
    assert "widget" not in sys.modules
    assert "widget.plugin" not in sys.modules


def test_an_entrypoint_inside_the_folder_resolves_to_its_file(tmp_path: Path):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())

    inspection = inspect_package(folder)

    assert inspection.entrypoint_file == folder / "plugin.py"
    assert inspection.problem is None
    assert inspection.consistent


def test_an_entrypoint_pointing_outside_the_folder_is_reported(tmp_path: Path):
    folder = _write_package(
        tmp_path, "widget", manifest=_manifest(entrypoint="json:loads")
    )

    inspection = inspect_package(folder)

    assert inspection.entrypoint_file is None
    assert not inspection.consistent
    assert "points outside" in (inspection.problem or "")


def test_a_folder_without_an_init_file_is_reported_as_not_a_package(tmp_path: Path):
    # A directory with no __init__.py is a namespace package: it resolves to no
    # single file, so the loader cannot show it is inside the trusted root.
    folder = _write_package(tmp_path, "widget", manifest=_manifest(), package=False)

    inspection = inspect_package(folder)

    assert not inspection.consistent
    assert "__init__.py" in (inspection.problem or "")


def test_a_folder_with_no_manifest_reports_that_and_nothing_else(tmp_path: Path):
    folder = _write_package(tmp_path, "widget")

    inspection = inspect_package(folder)

    assert inspection.has_manifest is False
    assert inspection.package is None
    assert inspection.consistent is False


def test_an_unparseable_or_unknown_field_manifest_is_reported_not_ignored(
    tmp_path: Path,
):
    broken = _write_package(tmp_path, "broken", manifest_text="{not json")
    smuggled = _write_package(
        tmp_path,
        "smuggled",
        manifest={**_manifest(package_id="example.smuggled"), "run_me": "exec()"},
    )

    assert inspect_package(broken).package is None
    assert inspect_package(broken).problem

    inspection = inspect_package(smuggled)
    assert inspection.package is None
    assert "run_me" in (inspection.problem or "")


def test_inspecting_a_folder_of_packages_resolves_each_against_that_folder(
    tmp_path: Path,
):
    _write_package(tmp_path, "alpha", manifest=_manifest(
        package_id="example.alpha", plugin_id="alpha",
        entrypoint="alpha.plugin:create_plugin",
    ))
    _write_package(tmp_path, "beta", manifest=_manifest(
        package_id="example.beta", plugin_id="beta",
        entrypoint="beta.plugin:create_plugin",
    ))

    inspections = inspect_directory(tmp_path)

    assert [item.folder.name for item in inspections] == ["alpha", "beta"]
    assert all(item.consistent for item in inspections)
    assert not (tmp_path / TRIPWIRE).exists()


def test_inspecting_a_folder_with_nothing_in_it_still_returns_a_result(
    tmp_path: Path,
):
    # "I looked and found nothing to check" is something a caller has to show a
    # person, not an empty list to skip silently past.
    inspections = inspect_directory(tmp_path)

    assert len(inspections) == 1
    assert inspections[0].has_manifest is False
