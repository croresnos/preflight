"""The three commands, including their exit codes.

``check`` is meant to be run against something you downloaded and have not read,
so two of its properties are load-bearing: it must never import the thing it is
inspecting, and it must exit non-zero when a package would be refused, so it can
sit in a script without anyone reading the output.

``init`` writes a file into a directory the user named. It must refuse to
overwrite one, and it must refuse to write a manifest whose entrypoint could
never resolve.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from preflight.cli import main

from test_inspect import _manifest, _write_package  # noqa: E402


def test_check_exits_zero_on_a_package_whose_paperwork_holds_up(tmp_path, capsys):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())

    assert main(["check", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "nothing was executed" in out
    assert "manifest      valid" in out
    assert "preflight did not run this code" in out


def test_check_exits_non_zero_when_a_package_would_be_refused(tmp_path, capsys):
    folder = _write_package(
        tmp_path, "widget", manifest=_manifest(entrypoint="json:loads")
    )

    assert main(["check", str(folder)]) == 1
    assert "would be refused" in capsys.readouterr().out


def test_check_never_imports_the_package_it_is_pointed_at(tmp_path, capsys, monkeypatch):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())
    monkeypatch.syspath_prepend(str(tmp_path))

    assert main(["check", str(folder)]) == 0

    assert not (tmp_path / "tripwire.log").exists()
    assert "widget" not in sys.modules


def test_check_on_a_package_with_no_manifest_says_so_and_points_at_init(
    tmp_path, capsys
):
    folder = _write_package(tmp_path, "widget")

    assert main(["check", str(folder)]) == 1
    out = capsys.readouterr().out
    assert "no manifest.json found" in out
    assert "it is the absence of one" in out
    assert "preflight init widget" in out


def test_check_lists_every_declared_tool_and_flags_the_ones_beyond_read(
    tmp_path, capsys
):
    folder = _write_package(
        tmp_path,
        "widget",
        manifest=_manifest(
            tools=[
                {"name": "widget.read", "risk": "read"},
                {"name": "widget.wipe", "risk": "destructive"},
            ]
        ),
    )

    main(["check", str(folder)])
    out = capsys.readouterr().out

    assert "declares 2 tools" in out
    assert "  widget.read" in out
    assert "! widget.wipe" in out
    assert "deletes things" in out


def test_check_on_a_missing_path_exits_two(tmp_path, capsys):
    assert main(["check", str(tmp_path / "nowhere")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_init_writes_a_manifest_that_check_then_accepts(tmp_path, capsys):
    folder = _write_package(tmp_path, "widget")

    assert main(["init", str(folder)]) == 0
    written = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert written["package_id"] == "local.widget"
    assert written["entrypoint"] == "widget.plugin:create_plugin"
    assert written["plugin"]["tools"] == []

    capsys.readouterr()
    assert main(["check", str(folder)]) == 0


def test_init_says_what_the_manifest_does_and_does_not_mean(tmp_path, capsys):
    folder = _write_package(tmp_path, "widget")

    main(["init", str(folder)])
    out = capsys.readouterr().out

    assert "what you PERMIT" in out
    assert "did not read its code" in out


def test_init_refuses_to_overwrite_an_existing_manifest_without_force(
    tmp_path, capsys
):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())
    original = (folder / "manifest.json").read_text(encoding="utf-8")

    assert main(["init", str(folder)]) == 2
    assert (folder / "manifest.json").read_text(encoding="utf-8") == original
    assert "already exists" in capsys.readouterr().err

    assert main(["init", str(folder), "--force"]) == 0
    assert (folder / "manifest.json").read_text(encoding="utf-8") != original


def test_init_refuses_a_folder_name_that_can_never_be_a_python_package(
    tmp_path, capsys
):
    # No manifest can make `import weather-tool` work, so writing one that
    # points at it would be writing a file that only looks like progress.
    folder = tmp_path / "weather-tool"
    folder.mkdir()

    assert main(["init", str(folder)]) == 2
    assert not (folder / "manifest.json").exists()
    err = capsys.readouterr().err
    assert "cannot be a Python package name" in err
    assert "weather-tool  ->  weather_tool" in err


def test_init_accepts_an_awkward_folder_name_when_given_an_explicit_entrypoint(
    tmp_path, capsys
):
    folder = tmp_path / "weather-tool"
    folder.mkdir()

    assert main(["init", str(folder), "--entrypoint", "elsewhere.plugin:build"]) == 0
    written = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert written["entrypoint"] == "elsewhere.plugin:build"


def test_demo_loads_one_plugin_and_refuses_three(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out

    assert out.count("LOADED") == 1
    assert out.count("REFUSED") == 3
    assert "1 loaded, 3 refused" in out
    assert "2 of the 3 stopped before any of their code ran" in out
    # collider is refused from its manifest alone, so its tripwire never fires.
    assert "[collider]" not in out
