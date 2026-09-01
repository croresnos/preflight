"""The built wheel carries the examples, so an installed copy can run the demo.

`preflight demo` is the fastest way to see what the gate refuses and why, and
the README tells people to reach it with a plain `pip install`. That only works
if the examples are inside the distribution -- they live outside `src/` and a
wheel does not collect them by default.

This is the failure the rest of the suite cannot see. Rename `examples/`, or
drop the force-include from pyproject.toml, and every other test stays green
while every installed copy of preflight loses its demo.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED = (
    "preflight/_examples/plugins/greeter/manifest.json",
    "preflight/_examples/plugins/greeter/__init__.py",
    "preflight/_examples/plugins/greeter/plugin.py",
    "preflight/_examples/plugins/trespasser/manifest.json",
    "preflight/_examples/plugins/collider/manifest.json",
    "preflight/_examples/plugins/impostor/manifest.json",
    "preflight/_examples/plugins/janitor/manifest.json",
)


@pytest.fixture(scope="module")
def wheel_contents(tmp_path_factory) -> frozenset[str]:
    """Every path inside a freshly built wheel.

    Building needs the backend, which pip fetches unless it is already present.
    A machine that cannot do that gets a skip rather than a failure: this test
    is about what the wheel contains, not about whether pip can reach an index.
    """
    destination = tmp_path_factory.mktemp("wheel")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(REPO_ROOT),
            "--no-deps",
            "-w",
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        pytest.skip(f"could not build a wheel here: {completed.stderr.strip()[-300:]}")

    # `preflight_gate`, not `preflight`: the distribution is named for what the
    # import is not. PyPI's `preflight` is an unrelated 2015 Django project.
    built = list(destination.glob("preflight_gate-*.whl"))
    assert len(built) == 1, f"expected exactly one wheel, got {built}"
    with zipfile.ZipFile(built[0]) as archive:
        return frozenset(archive.namelist())


def test_the_wheel_carries_every_example_package(wheel_contents):
    missing = [path for path in EXPECTED if path not in wheel_contents]

    assert not missing, f"the wheel would install without these: {missing}"


def test_the_wheel_carries_the_library_itself(wheel_contents):
    # Guards the force-include above from being the only thing that survives a
    # bad edit to the build config.
    assert "preflight/cli.py" in wheel_contents
    assert "preflight/registry.py" in wheel_contents


def test_the_wheel_carries_the_marker_that_makes_its_annotations_usable(wheel_contents):
    """pyproject claims `Typing :: Typed`, and PEP 561 decides whether that is true.

    Without a `py.typed` inside the installed package a type checker is required
    to ignore every annotation in it. The annotations are all still written; a
    dependent project's mypy would simply refuse to look at any of them, and the
    classifier would be a claim about a source tree nobody but the author has.
    """
    assert "preflight/py.typed" in wheel_contents


def test_the_wheel_carries_no_compiled_leftovers(wheel_contents):
    # The examples are copied out of a working tree that has been run, so this
    # is a live risk rather than a hypothetical one.
    litter = [
        path
        for path in wheel_contents
        if "__pycache__" in path or path.endswith(".pyc")
    ]

    assert not litter, f"build tree leaked into the wheel: {litter}"


def test_the_declared_version_and_the_importable_one_agree():
    """Two files state the version, and `preflight --version` reads only one.

    A wheel built from a pyproject that says 0.6.0 installs a package whose
    `--version` says whatever `__init__` says. Nothing else in the suite would
    notice them drifting apart, and the number is what a person quotes in a bug
    report.
    """
    import tomllib

    import preflight

    declared = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]

    assert declared == preflight.__version__
