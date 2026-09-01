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

import pytest

from preflight.inspect import inspect_directory, inspect_package, module_defines
from preflight.registry import PluginRegistry

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


def test_another_systems_manifest_is_reported_as_foreign_rather_than_invalid(
    tmp_path: Path,
):
    """A Figma plugin manifest. There is nothing wrong with this file.

    Lots of systems keep a manifest.json, so pointing `check` at one of theirs
    is a thing people will do on purpose, to find out what preflight is. Calling
    it INVALID is a false claim about a perfectly good file, and burying that
    claim under pydantic's dump is how a reader concludes preflight is broken.
    """
    folder = _write_package(
        tmp_path,
        "design_linter",
        manifest={
            "name": "Design Linter",
            "id": "1234567890123456789",
            "api": "1.0.0",
            "main": "code.js",
            "editorType": ["figma"],
        },
    )

    inspection = inspect_package(folder)

    assert inspection.package is None
    assert inspection.foreign_manifest is True
    problem = inspection.problem or ""
    assert "not one of preflight's" in problem
    assert len(problem.splitlines()) <= 4
    assert max(len(line) for line in problem.splitlines()) <= 68


def test_a_preflight_manifest_with_a_mistake_in_it_is_invalid_and_not_foreign(
    tmp_path: Path,
):
    # The line between the two reports. This file is unmistakably addressed to
    # preflight -- it is just wrong -- so the answer names the field, and does
    # not tell the author they were writing for some other tool.
    manifest = _manifest()
    del manifest["entrypoint"]
    folder = _write_package(tmp_path, "widget", manifest=manifest)

    inspection = inspect_package(folder)

    assert inspection.package is None
    assert inspection.foreign_manifest is False
    assert "entrypoint" in (inspection.problem or "")


def test_a_manifest_problem_is_reported_in_words_and_not_as_a_pydantic_dump(
    tmp_path: Path,
):
    # str(ValidationError) is several lines per error, each with a URL and an
    # echo of the input. Nine unknown fields is a wall nobody reads, so the
    # list is capped and the remainder counted.
    manifest = {**_manifest(), **{f"extra_{index}": index for index in range(9)}}
    folder = _write_package(tmp_path, "widget", manifest=manifest)

    problem = inspect_package(folder).problem or ""

    assert problem.startswith("9 problems with this manifest:")
    assert "... and 3 more" in problem
    assert len(problem.splitlines()) == 8
    assert "further information" not in problem
    assert "https://" not in problem


def test_inspecting_a_folder_of_packages_resolves_each_against_that_folder(
    tmp_path: Path,
):
    _write_package(
        tmp_path,
        "alpha",
        manifest=_manifest(
            package_id="example.alpha",
            plugin_id="alpha",
            entrypoint="alpha.plugin:create_plugin",
        ),
    )
    _write_package(
        tmp_path,
        "beta",
        manifest=_manifest(
            package_id="example.beta",
            plugin_id="beta",
            entrypoint="beta.plugin:create_plugin",
        ),
    )

    inspections = inspect_directory(tmp_path)

    assert [item.folder.name for item in inspections] == ["alpha", "beta"]
    assert all(item.consistent for item in inspections)
    assert not (tmp_path / TRIPWIRE).exists()


def test_refused_tools_reports_only_what_the_manifest_declared(tmp_path: Path):
    # The same question PluginRegistry answers from refuse_tool_risks, asked of
    # a package that is not being loaded. It reads declarations and nothing
    # else, so a tool the package never wrote down is invisible to it -- which
    # is exactly as much as the gate itself can see.
    folder = _write_package(
        tmp_path,
        "widget",
        manifest=_manifest(
            tools=[
                {"name": "widget.read", "risk": "read"},
                {"name": "widget.wipe", "risk": "destructive"},
                {"name": "widget.buy", "risk": "financial"},
            ]
        ),
    )

    inspection = inspect_package(folder)

    assert [tool.name for tool in inspection.refused_tools(["destructive"])] == [
        "widget.wipe"
    ]
    assert [
        tool.name for tool in inspection.refused_tools(["destructive", "financial"])
    ] == ["widget.wipe", "widget.buy"]
    assert inspection.refused_tools([]) == ()
    assert inspection.refused_tools(["credential"]) == ()


def test_refused_tools_on_a_package_with_no_readable_manifest_is_empty(
    tmp_path: Path,
):
    # No declaration is not a clean bill of health. It is the absence of one,
    # and this returns nothing rather than implying either.
    folder = _write_package(tmp_path, "widget")

    assert inspect_package(folder).refused_tools(["destructive"]) == ()


def test_inspecting_a_folder_with_nothing_in_it_still_returns_a_result(
    tmp_path: Path,
):
    # "I looked and found nothing to check" is something a caller has to show a
    # person, not an empty list to skip silently past.
    inspections = inspect_directory(tmp_path)

    assert len(inspections) == 1
    assert inspections[0].has_manifest is False


def test_inspection_refuses_an_oversized_manifest_without_reading_it(tmp_path: Path):
    folder = _write_package(tmp_path, "widget")
    manifest = folder / "manifest.json"
    manifest.write_text("x" * (PluginRegistry.MAX_MANIFEST_BYTES + 1), encoding="utf-8")

    inspection = inspect_package(folder)

    assert not inspection.consistent
    assert "exceeds 262144 bytes" in (inspection.problem or "")
    assert "was not read" in (inspection.problem or "")


def test_invalid_entrypoint_syntax_is_a_late_refusal(tmp_path: Path):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())
    (folder / "plugin.py").write_text("def create_plugin(:\n", encoding="utf-8")

    inspection = inspect_package(folder)

    assert inspection.consistent
    assert inspection.missing_attribute is None
    assert len(inspection.late_refusals()) == 1
    assert "invalid Python syntax" in inspection.late_refusals()[0]


def test_directory_inspection_reports_cross_package_identity_and_tool_collisions(
    tmp_path: Path,
):
    shared_tool = [{"name": "shared.read", "risk": "read"}]
    _write_package(
        tmp_path,
        "alpha",
        manifest=_manifest(
            package_id="example.same", plugin_id="alpha", tools=shared_tool
        ),
    )
    _write_package(
        tmp_path,
        "beta",
        manifest=_manifest(
            package_id="example.same", plugin_id="beta", tools=shared_tool
        ),
    )

    alpha, beta = inspect_directory(tmp_path)

    assert alpha.directory_refusals == ()
    assert any(
        "package id 'example.same'" in reason for reason in beta.directory_refusals
    )
    assert any(
        "tool name 'shared.read'" in reason for reason in beta.directory_refusals
    )


@pytest.mark.parametrize(
    "source",
    [
        "create_plugin, other = object(), object()\n",
        "for create_plugin in []:\n    pass\n",
        "with open(__file__) as create_plugin:\n    pass\n",
        "try:\n    pass\nexcept Exception as create_plugin:\n    pass\n",
        "match object():\n    case create_plugin:\n        pass\n",
        "if (create_plugin := object()):\n    pass\n",
    ],
)
def test_module_binding_analysis_handles_python_binding_forms(
    tmp_path: Path, source: str
):
    module = tmp_path / "plugin.py"
    module.write_text(source, encoding="utf-8")

    assert module_defines(module, "create_plugin")


def test_symlinked_entrypoint_source_outside_the_root_is_refused(tmp_path: Path):
    outside = tmp_path / "outside.py"
    outside.write_text("def create_plugin():\n    return None\n", encoding="utf-8")
    trusted_root = tmp_path / "plugins"
    folder = _write_package(
        trusted_root,
        "widget",
        manifest=_manifest(entrypoint="widget.plugin:create_plugin"),
        module=False,
    )
    try:
        (folder / "plugin.py").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    inspection = inspect_package(folder)

    assert not inspection.consistent
    assert "resolves outside" in (inspection.problem or "")
