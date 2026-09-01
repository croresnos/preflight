"""The output quoted in the documentation is the output the commands produce.

`test_docs.py` checks that the docs name real commands, install the real
distribution, and link to things that exist. It never runs anything, so for a
whole release the four `preflight try` transcripts in the manual described a
walkthrough the command no longer performed, and nothing failed. They were found
by hand and corrected by hand.

This runs the command and reads the fenced block back. A transcript opts in with
an HTML comment above its fence, which GitHub does not render:

    <!-- transcript: preflight demo -->
    <!-- transcript: python host.py | setup=try_no_init -->

The marker is not a convenience. Inference cannot work here, because the block
does not contain what you would need to reproduce it -- nothing inside a
`REFUSED weather ...` listing says it came from `python host.py` in a sandbox
with one file deleted. A heuristic would need a hand-written map from block to
command anyway, and its false negatives would be silent, which is the exact
failure this file exists to end.

The comparison is deliberately one-directional: every line the docs show must
appear, in order, in what the command printed. A line the command *gained* does
not fail. That is the benign direction -- an undocumented new line is a doc
improvement, a changed message is a doc telling a lie.
"""

from __future__ import annotations

import contextlib
import difflib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_inspect import _write_package  # noqa: E402

from preflight.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "docs/MANUAL.md")

#: A marked fence. The command runs; the body is what it must print.
_MARKER = re.compile(
    r"^<!--\s*transcript:\s*(?P<command>[^|>\n]+?)\s*"
    r"(?:\|\s*setup=(?P<setup>\w+)\s*)?"
    r"(?:\|\s*stream=(?P<stream>stdout|stderr)\s*)?-->\n"
    r"```[^\n]*\n(?P<body>.*?)^```",
    re.S | re.M,
)

#: `<anything>` and `...` in a documented line stand for whatever was there on
#: the day it was captured -- an absolute path, a Python prefix, an elision the
#: CLI itself printed. They match any run of non-newline characters.
_WILDCARD = re.compile(r"<[^<>\n]+>|\.\.\.")

#: The count below is a floor, not a target. Deleting a marker to make this file
#: pass is then a visible diff rather than quiet decay.
_EXPECTED_AT_LEAST = 11


@dataclass(frozen=True)
class Transcript:
    where: str  # "docs/MANUAL.md:806" -- the file and line to open on failure
    command: str
    setup: str
    stream: str
    body: str


def _transcripts() -> list[Transcript]:
    found: list[Transcript] = []
    for name in DOCS:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        for match in _MARKER.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            found.append(
                Transcript(
                    where=f"{name}:{line_no}",
                    command=match["command"].strip(),
                    setup=match["setup"] or "none",
                    stream=match["stream"] or "stdout",
                    body=match["body"],
                )
            )
    return found


def _normalise(text: str) -> str:
    """Make one expectation serve both CI legs.

    Backslash to forward slash is the rule that earns its place: it reconciles a
    block captured on Windows (`plugins\\`, `<python>\\Lib\\json`) with the same
    command's output on Linux, and no documented transcript distinguishes the two
    deliberately. Trailing whitespace goes because it is invisible in a diff and
    nobody can be asked to match it by eye.
    """
    text = text.replace("\r\n", "\n").replace("\\", "/")
    return "\n".join(line.rstrip() for line in text.split("\n")).strip("\n")


def _probe(line: str) -> re.Pattern[str]:
    """One documented line as a pattern, with its placeholders opened up."""
    return re.compile("[^\n]*".join(re.escape(part) for part in _WILDCARD.split(line)))


# --------------------------------------------------------------------------
# Setups. A named function that builds the state a transcript was captured in
# and returns the directory to run from. Deliberately not a fixture DSL: most
# transcripts need nothing, and the rest reuse state the CLI builds itself.
# --------------------------------------------------------------------------


def _setup_none(tmp: Path) -> Path:
    return tmp


def _setup_repo(tmp: Path) -> Path:
    """Run from the checkout, for transcripts of the bundled examples."""
    return REPO_ROOT


def _setup_try(tmp: Path) -> Path:
    with _chdir(tmp):
        assert main(["try", "weather-sandbox"]) == 0
    return tmp / "weather-sandbox"


def _setup_try_no_init(tmp: Path) -> Path:
    sandbox = _setup_try(tmp)
    (sandbox / "plugins" / "weather" / "__init__.py").unlink()
    return sandbox


def _setup_try_version_drift(tmp: Path) -> Path:
    sandbox = _setup_try(tmp)
    plugin = sandbox / "plugins" / "weather" / "plugin.py"
    plugin.write_text(
        plugin.read_text(encoding="utf-8").replace("1.0.0", "2.0.0"), "utf-8"
    )
    return sandbox


def _setup_unmanaged_weather(tmp: Path) -> Path:
    """A package that never heard of preflight, for the `create` walkthrough.

    `module=False`, and that is the whole point of the fixture. The shared helper
    writes a `plugin.py` defining `create_plugin`, which is exactly what a
    package in this situation does *not* have -- and with one present, `create`
    guesses the entrypoint that names it and this walkthrough silently stops
    demonstrating the case it is titled for.
    """
    _write_package(tmp / "plugins", "weather", module=False)
    return tmp


def _setup_empty_repo(tmp: Path) -> Path:
    (tmp / "random-repo").mkdir()
    return tmp


def _setup_saved_refuse(tmp: Path) -> Path:
    (tmp / "pyproject.toml").write_text("", encoding="utf-8")
    (tmp / "preflight.settings.json").write_text(
        json.dumps({"version": 1, "refuse": ["financial", "write"]}), encoding="utf-8"
    )
    return tmp


SETUPS = {
    "none": _setup_none,
    "repo": _setup_repo,
    "try": _setup_try,
    "try_no_init": _setup_try_no_init,
    "try_version_drift": _setup_try_version_drift,
    "unmanaged_weather": _setup_unmanaged_weather,
    "empty_repo": _setup_empty_repo,
    "saved_refuse": _setup_saved_refuse,
}


@contextlib.contextmanager
def _chdir(target: Path):
    previous = Path.cwd()
    os.chdir(target)
    try:
        yield
    finally:
        os.chdir(previous)


def _run(command: str, cwd: Path, capsys) -> str:
    """What the command printed, from a fresh interpreter when that matters.

    `demo` and the example hosts must be subprocesses for the reason
    `test_examples.py` already documents: a tripwire only fires on an import, and
    a warm interpreter has the example packages in `sys.modules` already, so an
    in-process run would be measuring the test runner. Everything else goes
    through `main` in this process, which is faster, keeps stdout and stderr
    apart, and inherits conftest's isolation of the user settings file.
    """
    argv = shlex.split(command)
    if argv[0] == "python" or "demo" in argv:
        rest = argv[1:] if argv[0] == "python" else ["-m", *argv]
        completed = subprocess.run(
            [sys.executable, *rest],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=cwd,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        return completed.stdout + completed.stderr
    with _chdir(cwd):
        main(argv[1:])
    captured = capsys.readouterr()
    return captured.out + captured.err


def _covered_lines(haystack: str, start: int, end: int) -> set[int]:
    """Which lines of ``haystack`` a match spanning ``start``..``end`` touched."""
    first = haystack.count("\n", 0, start)
    last = haystack.count("\n", 0, end)
    return set(range(first, last + 1))


def _assert_nothing_was_added(haystack: str, covered: set[int], where: str) -> None:
    """Every line the command printed must be accounted for by a documented one.

    The forward pass asks whether the documentation is still true. This asks
    whether it is still complete, and they are different failures: a command that
    *gains* a line leaves every documented line matching, so the forward pass
    alone reports a block that is quietly missing part of what the reader will
    see. That happened twice while this file was being written -- once to
    `preflight demo`, once to `preflight create` -- which is why this is a check
    and not a comment saying it would be nice to have one.

    Many-to-one is allowed on purpose: the docs hand-wrap long lines to render on
    GitHub, so two documented probes routinely match one printed line. What is
    not allowed is a printed line that no probe touched at all.
    """
    missing = [
        line
        for number, line in enumerate(haystack.split("\n"))
        if line.strip() and number not in covered
    ]
    if not missing:
        return
    listed = "\n".join(f"    {line}" for line in missing)
    raise AssertionError(
        f"{where}: this command prints {len(missing)} line(s) the documented "
        f"block does not contain.\n\n"
        f"{listed}\n\n"
        f"Fix: open {where} and add them to the fenced block, or replace the "
        f"varying part with a <placeholder>. A block out of date only in this "
        f"direction still reads as the whole output to whoever trusts it."
    )


def _assert_transcript(expected: str, actual: str, where: str) -> None:
    haystack = _normalise(actual)
    documented = _normalise(expected)
    cursor = 0
    covered: set[int] = set()
    for line in documented.split("\n"):
        probe = line.strip()
        if not probe:
            continue
        found = _probe(probe).search(haystack, cursor)
        if found is None:
            diff = "\n".join(
                difflib.unified_diff(
                    documented.split("\n"),
                    haystack.split("\n"),
                    fromfile=f"{where} (documented)",
                    tofile="what the command printed",
                    lineterm="",
                )
            )
            raise AssertionError(
                f"{where}: the documented output is no longer what this command "
                f"prints.\n\n"
                f"first line not found, searching forward from offset {cursor}:\n"
                f"    {probe}\n\n"
                f"{diff}\n\n"
                f"Fix: open {where} and paste the printed side into the fenced "
                f"block. Placeholders written as <...> or ... still match anything "
                f"on their line."
            )
        covered |= _covered_lines(haystack, found.start(), found.end())
        cursor = found.end()

    _assert_nothing_was_added(haystack, covered, where)


@pytest.mark.parametrize("transcript", _transcripts(), ids=lambda t: t.where)
def test_the_documented_output_is_what_the_command_prints(transcript, tmp_path, capsys):
    cwd = SETUPS[transcript.setup](tmp_path)
    printed = _run(transcript.command, cwd, capsys)
    _assert_transcript(transcript.body, printed, transcript.where)


def test_the_docs_still_carry_the_transcripts_they_used_to():
    """A marker removed is coverage removed, and it should look like it.

    Without this, the cheapest way to fix a failing transcript is to delete the
    comment above it, which passes review as a whitespace change.
    """
    count = len(_transcripts())
    assert count >= _EXPECTED_AT_LEAST, (
        f"only {count} marked transcripts, expected at least {_EXPECTED_AT_LEAST}. "
        f"If a block was legitimately removed, lower _EXPECTED_AT_LEAST in the "
        f"same commit so the loss is on the record."
    )
