"""The four commands, including their exit codes.

``check`` is meant to be run against something you downloaded and have not read,
so two of its properties are load-bearing: it must never import the thing it is
inspecting, and it must exit non-zero when a package would be refused, so it can
sit in a script without anyone reading the output.

``create`` writes a file into a directory the user named. It must refuse to
overwrite one, and it must refuse to write a manifest whose entrypoint could
never resolve.
"""

from __future__ import annotations

import json
import sys

import pytest

from preflight import __version__
from preflight.cli import _example_plugins, main

from test_inspect import _manifest, _write_package  # noqa: E402


def test_version_reports_the_installed_version_without_a_subcommand(capsys):
    # Two claims in one run. `command` is a required subparser, so --version has
    # to be answered before that requirement is enforced or it is unreachable on
    # its own -- passing no subcommand here is the point. And it exits 0, which
    # matters: `preflight --version` in a CI step should not read as a failure.
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"preflight {__version__}"


def test_the_demo_examples_are_found_without_reference_to_the_working_directory():
    """`preflight demo` has to work from anywhere, so this must not read the cwd.

    The path is derived from the module's own location, which is true of a
    source checkout and of a wheel alike. The wheel case cannot be proven from
    inside this test run -- see tests/test_packaging.py, which builds one.
    """
    found = _example_plugins()

    assert found is not None
    assert found.is_dir()
    assert (found / "janitor" / "manifest.json").is_file()


def test_a_path_that_does_not_exist_is_told_apart_from_one_that_is_a_file(
    tmp_path, capsys
):
    """Both are "not a directory". They are not the same mistake.

    The missing-path case is the first wall a beginner hits: `preflight create
    plugins/weather` is the obvious thing to type after reading the manual, and
    `create` deliberately never makes a folder -- it derives the package id, the
    entrypoint and the rename advice from the folder's name, so there has to be
    one. Saying so is the difference between a stop and a dead end.
    """
    missing = tmp_path / "not_here"
    assert main(["create", str(missing)]) == 2
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert "never creates one" in err

    a_file = tmp_path / "manifest.json"
    a_file.write_text("{}", encoding="utf-8")
    assert main(["check", str(a_file)]) == 2
    assert "is a file, not a directory" in capsys.readouterr().err


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


def test_check_on_a_package_with_no_manifest_says_so_and_points_at_create(
    tmp_path, capsys
):
    folder = _write_package(tmp_path, "widget")

    assert main(["check", str(folder)]) == 1
    out = capsys.readouterr().out
    assert "no manifest.json found" in out
    assert "it is the absence of one" in out
    assert "preflight create widget" in out


def test_check_on_another_systems_manifest_says_whose_it_is_and_stays_short(
    tmp_path, capsys
):
    # The moment a curious reader decides what preflight is. They point it at
    # the manifest.json they happen to have -- here a web app's -- and whatever
    # comes back is the whole impression.
    folder = _write_package(
        tmp_path,
        "webapp",
        manifest={
            "name": "Notes",
            "short_name": "Notes",
            "start_url": "/",
            "display": "standalone",
            "icons": [],
        },
    )

    assert main(["check", str(folder)]) == 1
    out = capsys.readouterr().out

    assert "not preflight's" in out
    assert "INVALID" not in out
    assert "preflight create" in out and "--force" in out
    # The whole report, not just the diagnosis. Twenty lines is something a
    # person reads; the pydantic dump this replaced ran past fifty.
    assert len(out.splitlines()) < 20


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


def test_check_exits_non_zero_on_a_risk_the_caller_refused(tmp_path, capsys):
    # Paperwork that is entirely in order. The only thing wrong with this
    # package is that the caller said they would not accept it.
    folder = _write_package(
        tmp_path,
        "widget",
        manifest=_manifest(tools=[{"name": "widget.wipe", "risk": "destructive"}]),
    )

    assert main(["check", str(folder)]) == 0
    capsys.readouterr()
    assert main(["check", str(folder), "--refuse", "destructive"]) == 1


def test_check_ignores_a_refused_risk_the_package_never_declared(tmp_path, capsys):
    folder = _write_package(
        tmp_path,
        "widget",
        manifest=_manifest(tools=[{"name": "widget.wipe", "risk": "destructive"}]),
    )

    assert main(["check", str(folder), "--refuse", "financial"]) == 0
    out = capsys.readouterr().out
    assert "a risk you refused" not in out
    assert "! widget.wipe" in out


def test_check_marks_the_refused_tool_and_names_the_policy_that_would_stop_it(
    tmp_path, capsys
):
    # The command line informs a decision that gets enforced somewhere else.
    # Printing the enforcing call by name is what keeps the two connected.
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

    main(["check", str(folder), "--refuse", "destructive"])
    out = capsys.readouterr().out

    assert "X widget.wipe" in out
    assert "  widget.read" in out
    assert "1 tool declares a risk you refused: widget.wipe (destructive)" in out
    assert "Policy(refuse_tool_risks={ToolRisk.DESTRUCTIVE})" in out
    assert "by your rule, not by preflight's" in out


def test_refuse_accepts_a_comma_separated_list_and_repetition_alike(tmp_path, capsys):
    folder = _write_package(
        tmp_path,
        "widget",
        manifest=_manifest(tools=[{"name": "widget.buy", "risk": "financial"}]),
    )

    assert main(["check", str(folder), "--refuse", "destructive,financial"]) == 1
    comma = capsys.readouterr().out

    assert (
        main(["check", str(folder), "--refuse", "destructive", "--refuse", "financial"])
        == 1
    )
    assert capsys.readouterr().out == comma


def test_refuse_rejects_an_unknown_risk_name_and_lists_the_valid_ones(
    tmp_path, capsys
):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())

    with pytest.raises(SystemExit) as exit_info:
        main(["check", str(folder), "--refuse", "spicy"])

    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "unknown risk 'spicy'" in err
    assert "destructive" in err
    assert "sensitive_disclosure" in err


def test_check_on_a_missing_path_exits_two(tmp_path, capsys):
    assert main(["check", str(tmp_path / "nowhere")]) == 2
    err = capsys.readouterr().err
    assert "does not exist" in err
    # Names the command it was given, not whichever one wrote the helper.
    assert "preflight check works on a package" in " ".join(err.split())


def test_create_writes_a_manifest_that_check_then_accepts(tmp_path, capsys):
    folder = _write_package(tmp_path, "widget")

    assert main(["create", str(folder)]) == 0
    written = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert written["package_id"] == "local.widget"
    assert written["entrypoint"] == "widget.plugin:create_plugin"
    assert written["plugin"]["tools"] == []

    capsys.readouterr()
    assert main(["check", str(folder)]) == 0


def test_create_works_from_inside_the_package_it_is_writing_for(
    tmp_path, capsys, monkeypatch
):
    # `cd widget && preflight create .` is the obvious way to run this, and
    # every name in the generated manifest comes from the folder's name --
    # which for '.' is the empty string until the path is resolved.
    folder = _write_package(tmp_path, "widget")
    monkeypatch.chdir(folder)

    assert main(["create", "."]) == 0
    written = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))

    assert written["package_id"] == "local.widget"
    assert written["plugin"]["plugin_id"] == "widget"
    assert written["entrypoint"] == "widget.plugin:create_plugin"


def test_create_says_what_the_manifest_does_and_does_not_mean(tmp_path, capsys):
    folder = _write_package(tmp_path, "widget")

    main(["create", str(folder)])
    out = capsys.readouterr().out

    assert "what you PERMIT" in out
    assert "did not read its code" in out


def test_create_refuses_to_overwrite_an_existing_manifest_without_force(
    tmp_path, capsys
):
    folder = _write_package(tmp_path, "widget", manifest=_manifest())
    original = (folder / "manifest.json").read_text(encoding="utf-8")

    assert main(["create", str(folder)]) == 2
    assert (folder / "manifest.json").read_text(encoding="utf-8") == original
    assert "already exists" in capsys.readouterr().err

    assert main(["create", str(folder), "--force"]) == 0
    assert (folder / "manifest.json").read_text(encoding="utf-8") != original


def test_create_refuses_a_folder_name_that_can_never_be_a_python_package(
    tmp_path, capsys
):
    # No manifest can make `import weather-tool` work, so writing one that
    # points at it would be writing a file that only looks like progress.
    folder = tmp_path / "weather-tool"
    folder.mkdir()

    assert main(["create", str(folder)]) == 2
    assert not (folder / "manifest.json").exists()
    err = capsys.readouterr().err
    assert "cannot be a Python package name" in err
    assert "weather-tool  ->  weather_tool" in err


def test_create_accepts_an_awkward_folder_name_when_given_an_explicit_entrypoint(
    tmp_path, capsys
):
    folder = tmp_path / "weather-tool"
    folder.mkdir()

    assert main(["create", str(folder), "--entrypoint", "elsewhere.plugin:build"]) == 0
    written = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert written["entrypoint"] == "elsewhere.plugin:build"


def test_demo_loads_two_plugins_and_refuses_three(capsys):
    before = list(sys.path)
    assert main(["demo"]) == 0
    out = capsys.readouterr().out

    # The demo is the only part of preflight that puts a folder on sys.path, and
    # it is reachable in-process as `cli.main(["demo"])`. It leaves the path as
    # it found it, or the caller's next import answers to a name they never
    # asked for -- which is what it did to the rest of this suite until 2026-08-03.
    assert sys.path == before

    assert out.count("LOADED") == 2
    assert out.count("REFUSED") == 3
    assert "2 loaded, 3 refused" in out
    assert "2 of the 3 stopped before any of their code ran" in out
    # collider is refused from its manifest alone, so its tripwire never fires.
    assert "[collider]" not in out


def test_demo_with_a_refused_risk_stops_the_janitor_while_it_is_still_inert(capsys):
    # The same plugin, the same manifest, a different host policy. This is the
    # one refusal in the demo that is nobody's fault.
    #
    # The tripwires are asserted in test_examples.py rather than here, because
    # they only fire on an import, and by this point in the session the example
    # packages are already in sys.modules. A tripwire assertion that passes for
    # that reason would be measuring pytest, not preflight.
    assert main(["demo", "--refuse", "destructive"]) == 0
    out = capsys.readouterr().out

    assert out.count("LOADED") == 1
    assert out.count("REFUSED") == 4
    assert "1 loaded, 4 refused" in out
    assert "3 of the 4 stopped before any of their code ran" in out
    assert "REFUSED  janitor" in out
    assert "risk 'destructive', which this host refuses" in out


def test_demo_refusing_destructive_does_not_catch_the_plugin_that_lied(capsys):
    # impostor declares two read-only tools and produces a destructive third
    # one after loading. --refuse acts on declarations, so it cannot see that.
    # This is the honest limit of the flag and it is worth pinning.
    assert main(["demo", "--refuse", "destructive"]) == 0
    out = capsys.readouterr().out

    assert "REFUSED impostor imported, then rejected" in " ".join(out.split())
    assert "does not match its validated package manifest" in out
    assert "preflight enforces declarations. It does not detect concealment." in out


def test_try_writes_a_sandbox_that_actually_loads(tmp_path, capsys):
    # The point of the command is that the thing it writes works before you
    # break it. If `check` refuses what `try` just produced, every instruction
    # printed underneath it is wrong.
    root = tmp_path / "sandbox"
    assert main(["try", str(root)]) == 0
    capsys.readouterr()

    assert (root / "host.py").is_file()
    assert (root / "plugins" / "weather" / "__init__.py").is_file()
    assert main(["check", str(root / "plugins" / "weather")]) == 0


def test_try_sandbox_manifest_and_runtime_manifest_agree(tmp_path, capsys):
    # The two copies of the plugin's identity are written by two different
    # string constants, so nothing but a test keeps them in step. Drift here
    # would make the sandbox refuse itself with check 17 on first run -- the
    # break the walkthrough saves for last.
    root = tmp_path / "sandbox"
    assert main(["try", str(root)]) == 0
    capsys.readouterr()

    package = root / "plugins" / "weather"
    on_disk = json.loads((package / "manifest.json").read_text(encoding="utf-8"))["plugin"]
    source = (package / "plugin.py").read_text(encoding="utf-8")

    assert on_disk["module_version"] in source
    assert on_disk["name"] in source
    assert on_disk["tools"][0]["name"] in source


def test_try_refuses_a_folder_that_is_not_empty(tmp_path, capsys):
    # Writing host.py over somebody's host.py is the one irreversible thing
    # this command could do.
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "host.py").write_text("mine\n", encoding="utf-8")

    assert main(["try", str(root)]) == 2
    assert (root / "host.py").read_text(encoding="utf-8") == "mine\n"
    assert "already exists and is not empty" in capsys.readouterr().err

    assert main(["try", str(root), "--force"]) == 0
    assert (root / "host.py").read_text(encoding="utf-8") != "mine\n"


def test_try_does_not_touch_sys_path(tmp_path, capsys):
    # `try` writes the sys.path line into host.py precisely because preflight
    # will not run it for you. It must not quietly do it here either.
    before = list(sys.path)
    assert main(["try", str(tmp_path / "sandbox")]) == 0
    capsys.readouterr()
    assert sys.path == before
