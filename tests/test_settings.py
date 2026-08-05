"""Saved settings, and the two properties that make saving them safe at all.

The important tests in this file are the first three. Everything else says the
settings resolved correctly; those three say a settings file cannot be used to
attack the gate, which is the only reason a configuration file is allowed to
exist in this project at all.

The attack has two shapes, and they are separate tests because the second one
survived the first fix. A planted file must not be able to *set* policy, and it
must not be able to *suppress* the policy a person actually wrote either -- a
rule silently downgraded to nothing is as good an outcome for an attacker as a
rule they chose themselves.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import preflight
from preflight.cli import main
from preflight.load import Policy
from preflight.manifest import Platform, ToolRisk
from preflight.registry import Edition
from preflight.settings import (
    SETTINGS_NAME,
    SettingsError,
    load_settings,
    save_setting,
    user_settings_path,
)

from test_inspect import _manifest, _write_package  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_user_config(tmp_path, monkeypatch):
    """Keep every test off the real user's settings file, in both directions.

    Without this a developer's own ``preflight settings`` would change what the
    suite asserts, and the suite would overwrite theirs.
    """
    home = tmp_path / "_config"
    home.mkdir()
    monkeypatch.setenv("APPDATA", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    return home


def _write_settings(folder: Path, document: dict) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / SETTINGS_NAME
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _project(tmp_path: Path) -> Path:
    """A project root, marked with .git so the upward walk stops there."""
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    return root


# --- the security rules ---------------------------------------------------


def test_a_settings_file_inside_an_inspected_package_sets_nothing(tmp_path):
    """A plugin's own folder may not configure the gate.

    The file below says "refuse nothing" and sits where the package's author
    controls. If discovery ever reached it, a package could turn off the rule
    that would have refused it.

    What stops it here is the *anchoring* rule -- the search climbs from the cwd,
    so the package's file is never a candidate in the first place. Measured by
    reverting: this test survives disabling the inside-the-folder check and fails
    when discovery is pointed at the inspected directory. The inside-the-folder
    check is the second line, and is covered by the two tests below it.
    """
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    package = root / "plugins" / "evil"
    _write_settings(package, {"version": 1, "refuse": []})

    settings = load_settings(cwd=root, inspected=package)

    assert settings.refuse == frozenset({ToolRisk.FINANCIAL})
    assert settings.origins["refuse"].scope == "project"


def test_a_planted_file_cannot_suppress_the_rules_a_person_wrote(tmp_path):
    """Rejecting a file must not take the project scope down with it.

    This is the same attack as above by a different route, and it is the one
    that survived the first implementation. Running ``preflight check .`` from
    *inside* a package makes the nearest settings file the package's own. An
    implementation that drops it and gives up leaves the real project rules
    unapplied -- so the planted file still gets what it wanted, by deletion
    rather than by assignment.
    """
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    package = root / "plugins" / "evil"
    _write_settings(package, {"version": 1, "refuse": []})

    # cwd is the package itself: the poisoned file is the nearest candidate.
    settings = load_settings(cwd=package, inspected=package)

    assert settings.refuse == frozenset({ToolRisk.FINANCIAL}), (
        "the planted file suppressed the project's real rule"
    )
    assert settings.ignored and settings.ignored[0].path.parent == package


def test_a_file_dropped_beside_a_package_cannot_reach_down_onto_it(tmp_path):
    """The attack that beats the inside-the-folder check by one directory.

    Unpacking an archive into ``downloads/`` and inspecting what came out is the
    ordinary thing to do, and the shell is very often sitting in ``downloads/``
    at the time. A settings file beside the package is not *inside* it, so the
    first check waves it through, and it is the nearest candidate, so the rules
    the person actually wrote further up are never reached.
    """
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    downloads = root / "downloads"          # unpacked, and marked by nothing
    _write_settings(downloads, {"version": 1, "refuse": []})
    package = downloads / "evil"
    package.mkdir()

    for where in (downloads, package):
        settings = load_settings(cwd=where, inspected=package)
        assert settings.refuse == frozenset({ToolRisk.FINANCIAL}), (
            f"a file beside the package disabled the real rule, from {where.name}"
        )
        assert any("above the folder" in item.reason for item in settings.ignored)


def test_a_hand_made_project_directory_still_governs_what_is_beneath_it(tmp_path):
    """The check above must not break the ordinary case it sits next to.

    A project the person made themselves holds its plugins in a subfolder, and
    its settings file is expected to apply to them.
    """
    root = _project(tmp_path)           # _project marks it with .git
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    package = root / "plugins" / "widget"
    package.mkdir(parents=True)

    settings = load_settings(cwd=root, inspected=package)

    assert settings.refuse == frozenset({ToolRisk.FINANCIAL})
    assert settings.ignored == ()


@pytest.mark.parametrize("marker", ["pyproject.toml", ".hg", ".preflight-root"])
def test_any_project_marker_counts_not_only_git(tmp_path, marker):
    root = tmp_path / "project"
    (root / "plugins").mkdir(parents=True)
    if marker == ".hg":
        (root / marker).mkdir()      # a directory, like .git
    else:
        (root / marker).touch()
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    package = root / "plugins" / "widget"
    package.mkdir()

    settings = load_settings(cwd=root, inspected=package)

    assert settings.refuse == frozenset({ToolRisk.FINANCIAL})


def test_a_forged_marker_inside_unpacked_content_is_a_known_limit(tmp_path):
    """Stated as a test so it is a documented boundary, not a surprise.

    A marker is a file, and an archive can contain files. A package that ships
    its own ``pyproject.toml`` beside its own settings file passes the check in
    :func:`is_project_root`, because at that point every file in the tree was
    chosen by the same party.

    This is why the module docstring calls markers a filter and not a lock, and
    why the only anchor preflight actually trusts is the user-scope file, which
    lives where nothing is ever unpacked. If this test ever starts failing, the
    defence got stronger and the docs need updating to match.
    """
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    downloads = root / "downloads"
    _write_settings(downloads, {"version": 1, "refuse": []})
    (downloads / "pyproject.toml").touch()          # shipped in the archive
    package = downloads / "evil"
    package.mkdir()

    settings = load_settings(cwd=downloads, inspected=package)

    assert settings.refuse == frozenset(), (
        "a forged marker no longer works -- good news, but update the docs"
    )


def test_discovery_never_walks_up_from_the_inspected_directory(tmp_path):
    """Only the cwd's ancestors are consulted, never the target's.

    Anyone who can place a folder can place a settings file beside it. If the
    search climbed from the thing being inspected, that file would govern the
    decision about it.
    """
    root = _project(tmp_path)
    elsewhere = tmp_path / "downloads"
    _write_settings(elsewhere, {"version": 1, "refuse": []})
    (elsewhere / ".git").mkdir()
    package = elsewhere / "evil"
    package.mkdir()

    # cwd is a project that refuses nothing in particular; the file above the
    # inspected package says "refuse nothing" and must not be read.
    settings = load_settings(cwd=root, inspected=package)

    assert settings.origins["refuse"].scope == "default"
    assert settings.ignored == ()


def test_load_plugins_decides_the_same_with_and_without_a_settings_file(
    tmp_path, monkeypatch
):
    """The runtime gate reads no file, measured rather than asserted.

    The file refuses ``read``, and the package declares a ``read`` tool. If
    ``load_plugins`` consulted settings at all, the two runs below would differ.
    """
    root = _project(tmp_path)
    monkeypatch.chdir(root)
    _write_package(
        root, "widget", manifest=_manifest(tools=[{"name": "widget.get", "risk": "read"}])
    )
    monkeypatch.syspath_prepend(str(root))

    def outcome() -> list[tuple[bool, str | None]]:
        report = preflight.load_plugins(root, allow=["example.widget"])
        return [(item.loaded, item.reason) for item in report.outcomes]

    settings_file = _write_settings(root, {"version": 1, "refuse": ["read"]})
    with_file = outcome()
    settings_file.unlink()
    without_file = outcome()

    assert with_file == without_file, "a settings file moved load_plugins' decision"


def test_the_gate_module_does_not_import_the_settings_module():
    """Structural proof of the same thing, independent of any one scenario.

    The import runs from settings into load, so the reverse is a cycle Python
    would refuse to build. That makes "the gate never reads disk" a property of
    the architecture rather than a convention someone has to remember.
    """
    source = Path(preflight.load.__file__).read_text(encoding="utf-8")
    imports = [
        line
        for line in source.splitlines()
        if line.startswith(("import ", "from ")) and "settings" in line
    ]

    assert imports == []


# --- precedence -----------------------------------------------------------


def test_project_beats_user_and_profile_beats_project(tmp_path, _isolate_user_config):
    root = _project(tmp_path)
    _write_settings(
        _isolate_user_config / "preflight", {"version": 1, "refuse": ["read"]}
    )
    # user_settings_path() appends preflight/settings.json, not our filename.
    user_settings_path().parent.mkdir(parents=True, exist_ok=True)
    user_settings_path().write_text(
        json.dumps({"version": 1, "refuse": ["read"]}), encoding="utf-8"
    )

    assert load_settings(cwd=root).refuse == frozenset({ToolRisk.READ})

    _write_settings(
        root,
        {
            "version": 1,
            "refuse": ["financial"],
            "profiles": {"agent": {"refuse": ["destructive", "write"]}},
        },
    )
    assert load_settings(cwd=root).refuse == frozenset({ToolRisk.FINANCIAL})
    assert load_settings(cwd=root).origins["refuse"].scope == "project"

    by_profile = load_settings(cwd=root, profile="agent")
    assert by_profile.refuse == frozenset({ToolRisk.DESTRUCTIVE, ToolRisk.WRITE})
    assert by_profile.origins["refuse"].scope == "profile"


def test_the_flag_replaces_the_saved_value_rather_than_adding_to_it(
    tmp_path, monkeypatch, capsys
):
    """A flag has to be able to loosen, or it is not an override.

    Someone reaching for --refuse at a prompt is usually trying to get *out* of
    what the file says. Union semantics would make that impossible.
    """
    root = _project(tmp_path)
    monkeypatch.chdir(root)
    _write_settings(root, {"version": 1, "refuse": ["financial"]})
    folder = _write_package(
        root, "widget", manifest=_manifest(tools=[{"name": "widget.pay", "risk": "financial"}])
    )

    # The saved rule refuses this package.
    assert main(["check", str(folder)]) == 1
    capsys.readouterr()

    # The flag names a different risk, and replaces rather than unions, so the
    # financial tool is no longer refused.
    assert main(["check", str(folder), "--refuse", "destructive"]) == 0


def test_a_profile_that_does_not_exist_is_named_along_with_the_ones_that_do(tmp_path):
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "profiles": {"agent": {"refuse": []}}})

    with pytest.raises(SettingsError) as problem:
        load_settings(cwd=root, profile="nope")

    assert "no profile named 'nope'" in str(problem.value)
    assert "agent" in str(problem.value)


# --- the bridge to a host -------------------------------------------------


def test_as_python_prints_a_snippet_that_builds_the_same_policy(
    tmp_path, monkeypatch, capsys
):
    """Run the printed code. Do not match its text.

    This is the whole point of the command: what it prints has to be the policy
    the CLI just used, or pasting it into a host silently changes the rules.
    """
    root = _project(tmp_path)
    monkeypatch.chdir(root)
    _write_settings(root, {"version": 1, "refuse": ["financial", "write"]})

    assert main(["settings", "--as-python"]) == 0
    snippet = capsys.readouterr().out

    captured: dict[str, Policy] = {}
    monkeypatch.setattr(
        preflight,
        "load_plugins",
        lambda *a, policy=None, **k: captured.update(policy=policy),
    )
    exec(compile(snippet, "<as-python>", "exec"), {})

    assert captured["policy"] == load_settings(cwd=root).as_policy()
    assert captured["policy"].refuse_tool_risks == frozenset(
        {ToolRisk.FINANCIAL, ToolRisk.WRITE}
    )


def test_as_python_says_so_when_no_policy_is_needed(tmp_path, monkeypatch, capsys):
    """Defaults are the strictest values, so the honest output is no Policy."""
    monkeypatch.chdir(_project(tmp_path))

    assert main(["settings", "--as-python"]) == 0
    out = capsys.readouterr().out

    assert "Policy(" not in out
    assert "strictest" in out


# --- malformed input ------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("{not json", "not valid JSON"),
        ("[]", "must contain a JSON object"),
        ('{"version": 99}', "understands version"),
        ('{"refuse": ["nonsense"]}', "unknown risk"),
        ('{"refuse": "financial"}', "must be a list"),
        ('{"nonsense": 1}', "unrecognised key"),
        ('{"allow": ["acme.evil"]}', "may not"),
    ],
)
def test_a_settings_file_that_cannot_be_used_says_why_and_exits_two(
    tmp_path, monkeypatch, capsys, text, expected
):
    """Exit 2, never 1. On `check`, 1 already means "would be refused"."""
    root = _project(tmp_path)
    monkeypatch.chdir(root)
    (root / SETTINGS_NAME).write_text(text, encoding="utf-8")

    assert main(["settings"]) == 2
    assert expected in capsys.readouterr().err


def test_an_allow_key_is_refused_with_the_reason_it_is_refused(tmp_path, capsys):
    """The one rejection that has to teach, rather than just stop.

    A settings file that could add package ids to an allowlist is the attack the
    whole design is arranged against, so the message says where an allowlist
    belongs instead.
    """
    root = _project(tmp_path)
    _write_settings(root, {"version": 1, "allow": ["acme.evil"]})

    with pytest.raises(SettingsError) as problem:
        load_settings(cwd=root)

    message = str(problem.value)
    assert "may not" in message
    assert "host's source" in message


# --- round trip -----------------------------------------------------------


def test_saving_a_setting_then_reading_it_back_reports_the_right_scope(
    tmp_path, monkeypatch, capsys
):
    root = _project(tmp_path)
    monkeypatch.chdir(root)

    assert main(["settings", "refuse", "financial,write"]) == 0
    assert (root / SETTINGS_NAME).is_file()

    settings = load_settings(cwd=root)
    assert settings.refuse == frozenset({ToolRisk.FINANCIAL, ToolRisk.WRITE})
    assert settings.origins["refuse"].scope == "project"

    capsys.readouterr()
    assert main(["settings"]) == 0
    shown = capsys.readouterr().out
    assert "financial, write" in shown
    # Every settings screen carries it, or the feature teaches the wrong model.
    assert "It does not apply to a" in shown


def test_clearing_a_setting_falls_back_rather_than_pinning_an_empty_value(
    tmp_path, monkeypatch
):
    """--clear removes the key, so the next layer down is heard again."""
    root = _project(tmp_path)
    monkeypatch.chdir(root)
    user_settings_path().parent.mkdir(parents=True, exist_ok=True)
    user_settings_path().write_text(
        json.dumps({"version": 1, "refuse": ["read"]}), encoding="utf-8"
    )

    assert main(["settings", "refuse", "financial"]) == 0
    assert load_settings(cwd=root).refuse == frozenset({ToolRisk.FINANCIAL})

    assert main(["settings", "refuse", "--clear"]) == 0
    fallen_back = load_settings(cwd=root)
    assert fallen_back.refuse == frozenset({ToolRisk.READ})
    assert fallen_back.origins["refuse"].scope == "user"


def test_a_profile_is_saved_into_the_same_file_not_a_second_one(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.chdir(root)

    assert main(["settings", "--profile", "research", "refuse", "financial"]) == 0

    document = json.loads((root / SETTINGS_NAME).read_text(encoding="utf-8"))
    assert document["profiles"]["research"]["refuse"] == ["financial"]
    assert list(root.glob("*.json")) == [root / SETTINGS_NAME]
    assert load_settings(cwd=root, profile="research").refuse == frozenset(
        {ToolRisk.FINANCIAL}
    )


def test_setting_a_value_without_one_asks_for_it_instead_of_guessing(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(_project(tmp_path))

    assert main(["settings", "refuse"]) == 2
    assert "--clear" in capsys.readouterr().err


def test_an_unwritable_target_fails_with_a_sentence(tmp_path, monkeypatch):
    """Not a stack trace. The person needs the path and the reason."""
    root = _project(tmp_path)
    # A directory where the settings file should be is refused by the OS on
    # every platform, without depending on permission bits Windows ignores.
    (root / SETTINGS_NAME).mkdir()

    with pytest.raises(SettingsError) as problem:
        save_setting("refuse", ["financial"], cwd=root)

    assert SETTINGS_NAME in str(problem.value)


# --- display and platform -------------------------------------------------


def test_where_names_both_files_whether_or_not_they_exist(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(_project(tmp_path))

    assert main(["settings", "--where"]) == 0
    out = capsys.readouterr().out

    assert "not created yet" in out
    assert "user" in out and "project" in out
    assert "It does not apply to a" in out


def test_the_user_path_follows_the_platform_convention(monkeypatch, tmp_path):
    """%APPDATA% on Windows, XDG elsewhere. Both are outside any plugin's reach."""
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))

    path = user_settings_path()

    expected = "roaming" if sys.platform == "win32" else "xdg"
    assert expected in str(path)
    assert path.name == "settings.json"
    assert path.parent.name == "preflight"


@pytest.mark.skipif(sys.platform != "win32", reason="case-insensitive paths")
def test_the_inside_check_is_case_insensitive_on_windows(tmp_path):
    """`C:\\Plugins` and `c:\\plugins` are one directory, and the check knows it.

    Comparing raw strings would let a difference in capitalisation walk straight
    through the rule this whole module rests on.
    """
    root = _project(tmp_path)
    package = root / "Plugins" / "Evil"
    _write_settings(package, {"version": 1, "refuse": []})
    _write_settings(root, {"version": 1, "refuse": ["financial"]})

    shouting = Path(str(package).upper())
    settings = load_settings(cwd=package, inspected=shouting)

    assert settings.refuse == frozenset({ToolRisk.FINANCIAL})
    assert settings.ignored


def test_edition_and_platform_round_trip_through_a_file(tmp_path):
    root = _project(tmp_path)
    _write_settings(
        root, {"version": 1, "edition": "internal", "platform": "linux"}
    )

    settings = load_settings(cwd=root)

    assert settings.edition is Edition.INTERNAL
    assert settings.platform is Platform.LINUX
    assert settings.as_policy().platform is Platform.LINUX
