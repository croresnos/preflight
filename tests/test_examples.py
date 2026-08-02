"""The examples do what the README says they do.

The README quotes the output of ``examples/host.py`` verbatim, which makes that
output a claim. This runs it in a fresh interpreter -- which also checks that a
clean clone can run it with nothing installed -- and pins the four outcomes.

The assertion that carries this file is ``"[collider]" not in output``. Every
other line here says a plugin was refused. That one says a plugin never ran.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOST = REPO_ROOT / "examples" / "host.py"


def _run_the_example_host() -> str:
    completed = subprocess.run(
        [sys.executable, str(HOST)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_the_example_host_loads_one_plugin_and_refuses_three():
    output = _run_the_example_host()

    # Refused for naming a module outside the trusted root, before importing it.
    assert "outside the trusted plugin root" in output
    # Refused for claiming a tool name greeter already owns, before importing it.
    assert "tool name collision: 'greeter.hello' is already owned by 'greeter'" in output
    # Refused for reporting a manifest other than the one it declared. This one is
    # necessarily after the import: there has to be an object to ask.
    assert "does not match its validated package manifest" in output

    # Exactly one plugin registered, and it is callable.
    assert "LOADED   Greeter" in output
    assert output.count("LOADED") == 1
    assert "greeter.hello -> greeter" in output
    assert "impostor.read_profile -> None" in output
    assert "Hello, world." in output


def test_the_refused_plugins_that_never_imported_left_no_trace():
    output = _run_the_example_host()

    # collider's package body prints on import. It never got one.
    assert "[collider]" not in output

    # The two that did import say so, which is what makes the absence above mean
    # something. A tripwire that can never fire proves nothing.
    assert "[greeter] top-level plugin code is executing" in output
    assert "[impostor] top-level plugin code is executing" in output
