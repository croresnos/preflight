"""`preflight check` and `load_plugins` must reach the same verdict.

The command's whole claim is that it answers, without importing anything, the
question a host answers at startup. For two of the four preload checks it did
not: `check` judged the declared risks and the paperwork, and never looked at
`supported_platforms` or at the release ring. A package the gate would refuse
printed "Paperwork is consistent" and exited `0`.

That is worse than a missing feature. The manual recommends putting
`preflight check` in CI *specifically* so a plugin that would be refused at
startup is caught at review time instead, and for half the checks the command
was quietly answering a smaller question than the one being asked of it.

Both paths now call `preflight.registry.preload_refusals`. These tests pin the
consequence rather than the refactor: the same package, judged twice, must come
back with the same answer in the same words. Rewording a refusal in the registry
and forgetting the command is exactly the drift this file exists to catch, and
matching the strings is what catches it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from test_inspect import _manifest, _write_package  # noqa: E402

from preflight import load_plugins
from preflight.cli import main
from preflight.inspect import inspect_package
from preflight.manifest import Platform
from preflight.registry import host_platform


def _other_platform() -> Platform:
    """A platform this test run is definitely not on."""
    running = host_platform()
    return Platform.LINUX if running is not Platform.LINUX else Platform.WINDOWS


def _package(root: Path, name: str, **manifest_changes) -> Path:
    """One plugin package on disk, with its manifest tweaked at the top level.

    The plugin it writes really does satisfy the ABI. That matters for the
    negative test below: the shared helper's stub returns ``None``, which the
    gate refuses *after* importing it, on a check `check` cannot make and does
    not claim to. Comparing the two paths needs a package whose only possible
    refusal is one they both get to see.
    """
    manifest = _manifest(
        package_id=f"example.{name}",
        plugin_id=name,
        entrypoint=f"{name}.plugin:create_plugin",
    )
    plugin_changes = manifest_changes.pop("plugin", {})
    manifest.update(manifest_changes)
    manifest["plugin"].update(plugin_changes)
    folder = _write_package(root, name, manifest=manifest)
    folder.joinpath("plugin.py").write_text(
        "from preflight import PluginManifest\n"
        f"_MANIFEST = PluginManifest.model_validate({manifest['plugin']!r})\n"
        "class Widget:\n"
        "    @property\n"
        "    def manifest(self):\n"
        "        return _MANIFEST\n"
        "def create_plugin():\n"
        "    return Widget()\n",
        encoding="utf-8",
    )
    return folder


def _gate_refusal(root: Path, package_id: str, folder: str) -> str | None:
    """What `load_plugins` says about one package, or ``None`` if it loaded."""
    # This window is safe for the stdlib names used below only because
    # `preflight.registry` has already imported them, so `sys.modules` answers
    # first. A case built on a stdlib module nothing has imported yet -- `wave`,
    # `colorsys` -- would resolve to the package written here and shadow the real
    # one for the rest of the session. That is the third regime, and it is the
    # reason `check` refuses every stdlib name rather than only the taken ones.
    sys.path.insert(0, str(root))
    try:
        report = load_plugins(root, allow=[package_id])
    finally:
        sys.path.remove(str(root))
    outcome = next(item for item in report.outcomes if item.folder == folder)
    return None if outcome.loaded else outcome.reason


def _assert_quotes_the_gate(from_the_gate: str, printed: str) -> None:
    """Every line of the gate's refusal appears, in order, in what `check` printed.

    Not a plain substring test, because a reason may run to several lines and
    both reports re-indent the later ones to sit under the reason column --
    `LoadReport.text` and `format_inspection` each do it, to their own column
    widths. Indentation is the report's business; the words are the contract.
    """
    cursor = 0
    for line in from_the_gate.splitlines():
        found = printed.find(line.strip(), cursor)
        assert found != -1, (
            f"check must quote the gate verbatim, and this line is missing.\n"
            f"missing line: {line.strip()!r}\n"
            f"gate said:\n{from_the_gate}\n\n"
            f"check printed:\n{printed}"
        )
        cursor = found + len(line.strip())


@pytest.mark.parametrize(
    "name, changes",
    [
        (
            "wrongplatform",
            {"plugin": {"supported_platforms": [_other_platform().value]}},
        ),
        ("experimental", {"release_ring": "experimental"}),
        ("internalonly", {"visibility": "internal", "release_ring": "beta"}),
    ],
)
def test_check_refuses_what_the_gate_refuses_and_says_the_same_thing(
    tmp_path, monkeypatch, capsys, name, changes
):
    """Three packages the gate turns away that `check` used to pass.

    Each one is well-formed: the manifest parses, the entrypoint resolves, and
    no tool declares a risk anybody refused. The only thing wrong with them is
    that this build will not take them -- which is precisely what a command
    claiming to predict the gate has to notice.
    """
    _package(tmp_path, name, **changes)
    monkeypatch.chdir(tmp_path)

    assert main(["check", name]) == 1
    printed = capsys.readouterr().out

    from_the_gate = _gate_refusal(tmp_path, f"example.{name}", name)
    assert from_the_gate is not None, "the gate should have refused this"
    _assert_quotes_the_gate(from_the_gate, printed)


def test_check_still_passes_a_package_this_build_would_load(tmp_path, monkeypatch):
    """The negative half. A widened check that refuses everything proves nothing."""
    _package(tmp_path, "fine")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "fine"]) == 0
    assert _gate_refusal(tmp_path, "example.fine", "fine") is None


def test_a_platform_the_host_does_support_is_not_a_refusal(tmp_path, monkeypatch):
    """`supported_platforms` naming this OS must not be read as a restriction."""
    _package(
        tmp_path, "supported", plugin={"supported_platforms": [host_platform().value]}
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "supported"]) == 0


def test_the_saved_edition_is_what_check_judges_against(tmp_path, monkeypatch):
    """A settings file that widens the edition must widen `check` too.

    `preflight settings` prints `edition` as being in force. If the command that
    consults settings ignored it, the display would be stating something untrue
    about the run the reader is about to make.
    """
    _package(tmp_path, "experimental", release_ring="experimental")
    (tmp_path / "preflight.settings.json").write_text(
        json.dumps({"version": 1, "edition": "development"}), encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")  # a project root
    monkeypatch.chdir(tmp_path)

    assert main(["check", "experimental"]) == 0, (
        "a development build accepts the experimental ring, and the settings "
        "file said this is one"
    )


def test_inspecting_a_refused_package_still_does_not_import_it(tmp_path):
    """The new checks must not have cost the command its one hard guarantee.

    `_write_package` plants a tripwire in each package body. Deciding that a
    package is refused for its platform is a decision made from parsed JSON, and
    it must stay one.
    """
    _package(
        tmp_path,
        "wrongplatform",
        plugin={"supported_platforms": [_other_platform().value]},
    )

    inspection = inspect_package(tmp_path / "wrongplatform")

    assert inspection.refusals(), "expected a platform refusal"
    assert not list(tmp_path.glob("*ran*")), "inspecting must not execute the package"
    assert "wrongplatform" not in sys.modules


def test_a_folder_named_after_a_builtin_is_refused_in_the_gates_exact_words(
    tmp_path, monkeypatch, capsys
):
    """The same divergence as above, in the branch `check` can be certain of.

    `time` is compiled into the interpreter, and `BuiltinImporter` sits ahead of
    `PathFinder` on `sys.meta_path` -- so the name is answered before any
    directory is consulted, in every process, whatever a host does to `sys.path`.
    No plugin folder called `time` is reachable by anyone.

    `check` used to resolve `time/plugin.py` by path arithmetic, find it sitting
    right there, and print "Paperwork is consistent" with exit 0. Both paths now
    produce the string from `registry.no_file_refusal`, so rewording one reword
    the other.
    """
    _package(tmp_path, "time")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "time"]) == 1
    printed = capsys.readouterr().out

    from_the_gate = _gate_refusal(tmp_path, "example.time", "time")
    assert from_the_gate is not None, "the gate should have refused this"
    _assert_quotes_the_gate(from_the_gate, printed)
    assert "Rename the plugin folder" in printed, "the refusal must say what to do"


def test_a_folder_named_after_a_stdlib_module_is_refused_but_not_word_for_word(
    tmp_path, monkeypatch, capsys
):
    """The other branch, and the one place the two cannot share one sentence.

    `json` is on disk rather than compiled in, and `preflight.registry` imports
    it -- so by the time any gate runs it is in `sys.modules` and `find_spec`
    hands back the standard library's copy. The gate's refusal therefore quotes
    an absolute path that `find_spec` resolved, and `check` may not ask
    `find_spec` anything: on a dotted name it executes the parent package.
    Guessing the path from `sysconfig` would be a guess about a different
    interpreter than the host's, and a wrong verbatim quote is worse than an
    honest paraphrase.

    So `check` writes its own sentence. What is pinned instead is that both
    refuse, and that both name the same module and the same root.
    """
    _package(tmp_path, "json")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "json"]) == 1
    printed = capsys.readouterr().out

    from_the_gate = _gate_refusal(tmp_path, "example.json", "json")
    assert from_the_gate is not None, "the gate should have refused this"
    assert "outside the trusted plugin root" in from_the_gate

    root = tmp_path.resolve()
    assert "entrypoint module 'json'" in printed
    assert "is a standard library module name" in printed
    assert f"outside the trusted plugin root '{root}'" in printed
    assert "Rename the plugin folder and the entrypoint together." in printed


def test_a_name_that_only_looks_like_a_stdlib_module_is_still_accepted(
    tmp_path, monkeypatch
):
    """The negative half, and the reason the check matches whole names only.

    Matching on prefixes would refuse every package whose folder merely starts
    with a stdlib word, which is a large fraction of the plausible ones.
    """
    _package(tmp_path, "jsonish")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "jsonish"]) == 0
    assert _gate_refusal(tmp_path, "example.jsonish", "jsonish") is None


def test_calling_a_package_unreachable_still_does_not_import_it(tmp_path):
    """The new check must not have cost the command its one hard guarantee.

    Deciding that a name is one the interpreter already owns is a lookup in two
    frozensets, and it has to stay one. `_write_package` plants a tripwire in
    each package body.
    """
    _package(tmp_path, "time")

    inspection = inspect_package(tmp_path / "time")

    assert inspection.refusals(), "expected an unreachable-name refusal"
    assert not list(tmp_path.glob("*ran*")), "inspecting must not execute the package"
    assert "time.plugin" not in sys.modules


def _package_missing_its_attribute(root: Path, name: str, *, body: str) -> Path:
    """A package whose entrypoint names an attribute its module does not define."""
    folder = _package(root, name)
    folder.joinpath("plugin.py").write_text(body, encoding="utf-8")
    return folder


def test_a_package_with_no_create_plugin_is_refused_by_both(tmp_path, monkeypatch):
    """The other half of the entrypoint string, and the sibling of every test above.

    `check` verified that the entrypoint's *module* resolves inside the trusted
    root and said nothing about the `:attribute` half -- so a package with no
    `create_plugin` printed "Paperwork is consistent", exited `0`, and was then
    refused at startup. It is the first thing a newcomer gets wrong, and it was
    the one thing this command would not mention.
    """
    _package_missing_its_attribute(
        tmp_path, "widget", body="def build_it():\n    return None\n"
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "widget"]) == 1

    refusal = _gate_refusal(tmp_path, "example.widget", "widget")
    assert refusal is not None
    assert "has no attribute 'create_plugin'" in refusal


def test_a_missing_attribute_is_reported_as_costing_the_package_its_import(
    tmp_path, capsys, monkeypatch
):
    """This refusal arrives after the code has run, and the report must say so.

    Every other reason `check` prints is one a host reaches with the package
    still inert on disk. This one is not: the gate resolves the module, imports
    it, and only then asks for the attribute. Filing it under "reasons a host
    would refuse this before importing it" would be a lie told by the one
    command whose subject is what executes -- so it has its own list, and the
    two are asserted separately here to keep them that way.
    """
    _package_missing_its_attribute(
        tmp_path, "widget", body="def build_it():\n    return None\n"
    )
    monkeypatch.chdir(tmp_path)

    inspection = inspect_package(tmp_path / "widget")
    assert inspection.refusals() == ()
    assert len(inspection.late_refusals()) == 1

    assert main(["check", "widget"]) == 1
    printed = capsys.readouterr().out
    assert "AFTER importing it" in printed
    assert "not before it had run" in printed


def test_an_attribute_defined_behind_a_conditional_is_still_found(
    tmp_path, monkeypatch
):
    """A `def` inside `if` is a module attribute. A `def` inside a `def` is not.

    Both are nested in the syntax tree and only one of them binds a name the
    gate's `getattr` can reach, so the scan has to descend into the statements
    that carry module-level code and stop at the ones that open a scope.
    """
    _package_missing_its_attribute(
        tmp_path,
        "widget",
        body=(
            "import sys\n"
            "if sys.version_info >= (3, 11):\n"
            "    def create_plugin():\n"
            "        return None\n"
            "else:\n"
            "    def create_plugin():\n"
            "        return None\n"
        ),
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "widget"]) == 0


def test_an_attribute_only_a_function_body_defines_is_not_found(tmp_path, monkeypatch):
    """The negative half of the test above, and the reason it is not a plain search.

    `create_plugin` appears in this file, at the top of a line, after a `def`.
    Grepping for it would pass. It is a local name in another function and the
    gate cannot reach it.
    """
    _package_missing_its_attribute(
        tmp_path,
        "widget",
        body=("def factory():\n    def create_plugin():\n        return None\n"),
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "widget"]) == 1


@pytest.mark.parametrize(
    "body",
    [
        "def __getattr__(name):\n    return None\n",
        "from os.path import *\n",
    ],
    ids=["module __getattr__", "star import"],
)
def test_a_module_that_can_invent_names_is_given_the_benefit_of_the_doubt(
    tmp_path, monkeypatch, body
):
    """A file that admits it might produce names it does not contain gets no verdict.

    `check`'s exit code is meant to be trustworthy enough to gate CI on. A false
    `1` -- refusing a package that would have loaded -- is the failure that makes
    people stop believing it, so where the syntax tree cannot answer, this stays
    quiet rather than guess.
    """
    _package_missing_its_attribute(tmp_path, "widget", body=body)
    monkeypatch.chdir(tmp_path)

    assert main(["check", "widget"]) == 0


def test_looking_for_the_attribute_does_not_import_the_package(tmp_path):
    """Reading a file is not running it, and this is the assertion that says so.

    The scan opens the package's own source, which nothing else in `inspect.py`
    does. `ast.parse` builds a tree and evaluates none of it -- but the whole
    command rests on that being true, so it is checked rather than asserted in a
    docstring. `_write_package` plants a tripwire in each package body.
    """
    _package_missing_its_attribute(
        tmp_path, "widget", body="def build_it():\n    return None\n"
    )

    inspection = inspect_package(tmp_path / "widget")

    assert inspection.late_refusals(), "expected a missing-attribute refusal"
    assert not list(tmp_path.glob("*ran*")), "inspecting must not execute the package"
    assert "widget" not in sys.modules
