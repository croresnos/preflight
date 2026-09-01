"""The documentation makes checkable claims. These check them.

Every defect this file guards against was a real one, found by reading the docs
against the code before 0.6.0:

- ``docs/MANUAL.md`` told people to run ``pip install preflight``. PyPI's
  ``preflight`` is an unrelated Django project last released in 2015, so the one
  instruction everybody follows first installed somebody else's package.
- The README's FAQ told people to run ``preflight init``. There has never been
  an ``init``; the command is ``create``.
- The manual showed ``preflight check ./plugins/*``, which cannot work --
  ``check`` takes exactly one path and argparse exits ``2`` on the rest.
- A section cross-reference pointed at the wrong section.

None of these would have been caught by a test of the library, because none of
them were wrong about the library. They were wrong about how to reach it, which
is the only part of a project that every single user touches.

The README's central credibility claim gets a test too: *"Every row names the
test that proves it. If you doubt a row, run that test."* A renamed test would
turn that table into a list of things nobody can run, silently.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from preflight.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = (REPO_ROOT / "README.md", REPO_ROOT / "docs" / "MANUAL.md")

#: The distribution on PyPI. Not ``preflight``, which is taken -- see the module
#: docstring. The import name and the console script are still ``preflight``.
DISTRIBUTION = "preflight-gate"

#: Words the docs have called commands that are not commands. ``init`` was in
#: the README's FAQ twice. Keeping the name here rather than deleting the
#: memory of it means the same paragraph cannot come back.
NEVER_COMMANDS = frozenset({"init", "scan", "install", "validate", "audit"})

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_INLINE = re.compile(r"`([^`\n]+)`")
_HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$", re.M)
#: Markdown links, and the raw ``<a href>`` ones the manual uses inside tables.
#: Both forms have to be read: the only broken cross-document link in the docs
#: at 0.6.0 was an HTML one, hiding from a check that knew about markdown alone.
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)[^)]*\)|<a href=\"([^\"]+)\"")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_spans(text: str) -> list[str]:
    """Every fenced block and inline span, which is where instructions live.

    Prose says "preflight refuses"; only code says "preflight refuse". Scanning
    the whole document would drown the signal in ordinary English.
    """
    return _FENCE.findall(text) + _INLINE.findall(text)


def _anchor(heading: str) -> str:
    """A heading rendered the way GitHub slugifies it for `#` links.

    Each space becomes one hyphen and runs are *not* collapsed, which is what
    makes ``in order - and`` anchor as ``in-order--and``: the em-dash is dropped
    as punctuation and the two spaces around it each become a hyphen. Collapsing
    them here would fail every heading containing a dash, which is most of them.
    """
    slug = re.sub(r"[^\w\s-]", "", heading.strip().lower().replace("`", ""))
    return slug.replace(" ", "-")


@pytest.fixture(scope="module")
def commands() -> frozenset[str]:
    """Every subcommand the CLI actually has, read off the parser itself.

    Derived rather than listed, so a command that is added, renamed or removed
    cannot leave this file asserting yesterday's truth.
    """
    subparsers = [
        action
        for action in build_parser()._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    assert len(subparsers) == 1, "expected one subparser group"
    return frozenset(subparsers[0].choices)


# --- the install instruction ----------------------------------------------


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name)
def test_every_install_instruction_names_the_real_distribution(doc):
    """`pip install preflight` installs an unrelated 2015 Django package.

    This is the highest-consequence sentence in the documentation: it is the
    first thing anybody types and the only one they cannot verify for themselves
    beforehand. The manual carried the wrong version of it until 0.6.0.
    """
    lines = [
        line.strip()
        for line in _read(doc).splitlines()
        if "pip install" in line and "pytest" not in line
    ]

    assert lines, f"{doc.name} should tell somebody how to install this"
    for line in lines:
        assert DISTRIBUTION in line, (
            f"{doc.name} says {line!r}.\n"
            f"PyPI's `preflight` is somebody else's package. Use {DISTRIBUTION!r}."
        )


# --- the commands ----------------------------------------------------------


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name)
def test_no_document_calls_a_non_command_a_command(doc, commands):
    """No word in :data:`NEVER_COMMANDS` may appear where a command goes.

    Two positions count, because the defect appeared in the second one. A
    reader treats ``preflight init ./thing`` in a code block as an instruction,
    and they treat "``check`` and ``init`` cover the other case" as one too --
    which is what the README's FAQ said. Both read as something to run, and
    neither was.

    Matching a list of names rather than "any word that is not a command" is
    deliberate. The docs are full of backticked field names and prose, and a
    test that flagged all of them would be turned off within a week.
    """
    text = _read(doc)
    invoked = set(
        re.findall(
            r"(?<!from )\bpreflight ([a-z][a-z0-9_-]*)", "\n".join(_code_spans(text))
        )
    )
    bare = {
        span for span in _INLINE.findall(text) if re.fullmatch(r"[a-z][a-z0-9_]*", span)
    }
    pretenders = sorted((invoked | bare) & NEVER_COMMANDS - commands)

    assert not pretenders, (
        f"{doc.name} presents {pretenders} as though they were commands.\n"
        f"Real commands: {sorted(commands)}"
    )


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name)
def test_no_documented_check_invocation_passes_more_than_one_path(doc):
    """`check` takes exactly one path, and a shell glob is not one path.

    The manual recommended `preflight check ./plugins/*` for CI. The shell
    expands that to as many arguments as there are folders, and argparse exits
    `2` with "unrecognized arguments" -- which in CI reads as a broken pipeline
    rather than as bad advice.
    """
    for block in _code_spans(_read(doc)):
        for line in block.splitlines():
            command = line.strip()
            if not command.startswith("preflight check "):
                continue
            # `preflight check | weather\ | nothing was executed` is the report's
            # own header, quoted from a real run. It begins with the same words
            # and is not an invocation of anything.
            if "|" in command:
                continue
            # Strip a trailing shell comment: the docs annotate their examples.
            command = command.split("#", 1)[0].strip()

            # Only the run of bare words before the first flag can be paths; a
            # flag's own value (`--profile production`) is not one.
            arguments: list[str] = []
            for word in command.split()[2:]:
                if word.startswith("-"):
                    break
                arguments.append(word)

            assert len(arguments) <= 1, (
                f"{doc.name}: {command!r} passes {arguments} to a command that "
                f"takes exactly one path."
            )
            assert not any("*" in word for word in arguments), (
                f"{doc.name}: {command!r} relies on a shell glob. `check` takes "
                f"one path, and the shell hands it several."
            )


# --- the cross-references --------------------------------------------------


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name)
def test_every_internal_link_points_at_something_that_exists(doc):
    """Section links and anchors, both of which have gone stale before now."""
    text = _read(doc)
    broken: list[str] = []

    for markdown, html in _LINK.findall(text):
        target = markdown or html
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _, anchor = target.partition("#")

        if path_part:
            # `../../commit/<sha>` and friends are GitHub-relative URLs that
            # resolve on the rendered page and to nothing on disk. Only files
            # this repository actually contains are checkable here.
            if not path_part.endswith(".md"):
                continue
            resolved = (doc.parent / path_part).resolve()
            if not resolved.exists():
                broken.append(f"{target} -> no such file")
                continue
            body = _read(resolved)
        else:
            resolved, body = doc, text

        if anchor and resolved.suffix == ".md":
            anchors = {_anchor(heading) for heading in _HEADING.findall(body)}
            if anchor not in anchors:
                broken.append(f"{target} -> no heading in {resolved.name}")

    assert not broken, f"{doc.name} has dead links:\n  " + "\n  ".join(broken)


# --- the claim the whole README rests on -----------------------------------


def test_every_test_the_docs_cite_by_name_actually_exists():
    """ "Every row names the test that proves it. If you doubt a row, run it."

    That sentence is the README's argument for being believed, and it is only
    worth anything while the names resolve. Renaming a test is an ordinary thing
    to do and nothing else in this repository would notice the table going out
    of date.
    """
    suite = "\n".join(
        _read(path) for path in sorted((REPO_ROOT / "tests").glob("test_*.py"))
    )
    defined = set(re.findall(r"^def (test_\w+)", suite, re.M))

    cited = {
        span
        for doc in DOCS
        for span in _INLINE.findall(_read(doc))
        if span.startswith("test_") and re.fullmatch(r"test_\w+", span)
    }
    assert cited, "the docs are supposed to cite tests by name"

    missing = sorted(cited - defined)
    assert not missing, "the docs name tests that no longer exist:\n  " + "\n  ".join(
        missing
    )


def test_the_api_reference_names_only_things_that_are_actually_exported():
    """Section 16 exists because a reader resorted to `dir(preflight)` without it.

    A reference table that has drifted is worse than the `dir()` call it replaced:
    that at least tells the truth. Both directions are checked -- a name the
    package no longer exports, and one it has gained that nobody wrote down.

    Against `__all__` rather than `dir()`. `dir()` also reports whichever
    submodules happen to have been imported by the time this runs, which makes it
    a fact about the test session; `__all__` is the API the package declares.
    """
    import preflight

    section = _read(REPO_ROOT / "docs" / "MANUAL.md").split(
        "## 16. Everything `import preflight` gives you"
    )
    assert len(section) == 2, "section 16 is missing or its heading changed"

    # The tables only. The closing paragraph names the four submodules in order
    # to say they are *not* the API, and reading it as a citation would make the
    # section contradict itself.
    tables = section[1].split("### Not part of the API")[0]
    # The first column of each table row, and nothing else. Prose mentions do not
    # count in either direction: the word "manifest" appears in this section as
    # the name of the `Plugin` protocol's property, which is not a claim that the
    # `preflight.manifest` submodule is part of the API. A row's first cell is
    # the only place this section actually declares an export.
    cited: set[str] = set()
    for row in re.findall(r"^\| (.+?) \|", tables, re.M):
        cited |= {span.split("(", 1)[0] for span in _INLINE.findall(row)}
    exported = set(preflight.__all__)

    missing = sorted(exported - cited)
    assert not missing, "section 16 does not mention: " + ", ".join(missing)

    invented = sorted(
        name for name in cited & set(dir(preflight)) if name not in exported
    )
    assert not invented, "section 16 names things that are not exported: " + ", ".join(
        invented
    )
