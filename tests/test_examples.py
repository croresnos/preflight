"""The examples do what the README says they do.

The README quotes the output of ``examples/host.py`` verbatim, which makes that
output a claim. This runs it in a fresh interpreter -- which also checks that a
clean clone can run it with nothing installed -- and pins the five outcomes.

The assertion that carries this file is ``"[collider]" not in output``. Every
other line here says a plugin was refused. That one says a plugin never ran.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOST = REPO_ROOT / "examples" / "host.py"


def _run(*command: str) -> str:
    completed = subprocess.run(
        [sys.executable, *command],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def _run_the_example_host() -> str:
    return _run(str(HOST))


def _run_the_demo(*flags: str) -> str:
    """The CLI demo in a fresh interpreter.

    A tripwire only fires on an import, and an in-process test that has already
    run the demo once finds the example packages in ``sys.modules``. Every claim
    about which plugins printed a tripwire has to be made in an interpreter that
    has not loaded them before, or it is measuring the test runner.
    """
    return _run("-m", "preflight", "demo", *flags)


def test_the_example_host_loads_two_plugins_and_refuses_three():
    output = _run_the_example_host()

    # Refused for naming a module outside the trusted root, before importing it.
    assert "outside the trusted plugin root" in output
    # Refused for claiming a tool name greeter already owns, before importing it.
    assert "tool name collision: 'greeter.hello' is already owned by 'greeter'" in output
    # Refused for reporting a manifest other than the one it declared. This one is
    # necessarily after the import: there has to be an object to ask. The refusal
    # names the smuggled tool, which is the whole reason the example exists --
    # "does not match" alone would leave the reader to find it themselves.
    assert "does not match its validated package manifest" in output
    assert "tools -- undeclared in the manifest: impostor.purge_all_records" in output

    # Two plugins registered, and the greeter is callable.
    assert "LOADED   greeter" in output
    assert "Greeter 1.0.0 - 1 tool" in output
    assert output.count("LOADED") == 2
    assert "2 loaded, 3 refused" in output
    assert "2 of the 3 stopped before any of their code ran" in output
    assert "greeter.hello -> greeter" in output
    assert "impostor.read_profile -> None" in output
    assert "Hello, world." in output


def test_this_host_passes_no_policy_so_a_destructive_declaration_is_no_obstacle():
    # janitor declares a tool that deletes things, honestly, and loads anyway.
    # Nothing is wrong with it and this host never said it minded. The refusal
    # is available -- Policy(refuse_tool_risks=...) -- and it is the host's to
    # ask for, which is the whole shape of the project in one plugin.
    output = _run_the_example_host()

    assert "LOADED   janitor" in output
    assert "Janitor 1.0.0 - 1 tool" in output


def test_the_refused_plugins_that_never_imported_left_no_trace():
    output = _run_the_example_host()

    # collider's package body prints on import. It never got one.
    assert "[collider]" not in output

    # The three that did import say so, which is what makes the absence above
    # mean something. A tripwire that can never fire proves nothing.
    assert "[greeter] top-level plugin code is executing" in output
    assert "[impostor] top-level plugin code is executing" in output
    assert "[janitor] top-level plugin code is executing" in output


def test_refusing_a_declared_risk_stops_the_janitor_before_it_is_imported():
    # The comparison this whole example exists to make. Same package, same
    # manifest, same gate -- the only thing that changed is what the host said
    # it would accept, and the plugin's code never ran.
    permissive = _run_the_demo()
    strict = _run_the_demo("--refuse", "destructive")

    assert "[janitor] top-level plugin code is executing" in permissive
    assert "[janitor]" not in strict

    assert "2 loaded, 3 refused" in permissive
    assert "1 loaded, 4 refused" in strict


def test_refusing_a_declared_risk_cannot_reach_a_risk_that_was_never_declared():
    # impostor is refused under both runs, and for the same reason under both:
    # it reported a manifest other than the one it declared. --refuse never had
    # anything to act on, because impostor's manifest declares only read tools.
    # A gate that enforces declarations is blind to concealment by construction,
    # and this is the test that says so out loud.
    strict = _run_the_demo("--refuse", "destructive")

    # It imported, so the flag did not stop it, and it was refused afterwards.
    assert "[impostor] top-level plugin code is executing" in strict
    assert "does not match its validated package manifest" in strict

    # The flag fired exactly once across all five packages, and janitor is the
    # one it fired on -- the package that said what it would do.
    assert strict.count("which this host refuses") == 1
    assert "package 'example.janitor' declares tool 'janitor.purge_cache'" in strict
