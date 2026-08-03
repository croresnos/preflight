"""``load_plugins`` is a shorter way to call the registry, not a weaker one.

The convenience this layer adds is discovery: the host no longer writes the loop
over ``manifest.json`` files by hand. The risk that comes with discovery is that
finding a package starts to imply loading it, so the assertion that carries this
file is ``test_a_package_on_disk_but_not_in_allow_is_never_imported``.

The rest is about the report. ``Outcome.code_ran`` is the field a person should
read before trusting a refusal, and it is recorded from the import itself rather
than guessed from which error came back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from preflight import Policy, ToolRisk, load_plugins

TRIPWIRE = "tripwire.log"

_PLUGIN_PY = """\
from preflight import PluginManifest, Tool, ToolRisk

_MANIFEST = PluginManifest(
    plugin_id={plugin_id!r},
    name={name!r},
    module_version="1.0.0",
    tools=[Tool(name={tool!r}, risk=ToolRisk({risk!r}))],
)


class _Plugin:
    @property
    def manifest(self):
        return _MANIFEST

    def hello(self):
        return "hello from " + {plugin_id!r}


def create_plugin():
    return _Plugin()
"""


def _write_plugin(
    root: Path,
    folder: str,
    *,
    package_id: str,
    plugin_id: str | None = None,
    tool: str | None = None,
    risk: str = "read",
    declared_plugin_id: str | None = None,
) -> Path:
    """Write a real, importable plugin package with a tripwire in its body."""
    plugin_id = plugin_id or folder
    tool = tool or f"{plugin_id}.do"
    directory = root / folder
    directory.mkdir(parents=True)
    directory.joinpath("__init__.py").write_text(
        f"from pathlib import Path\n"
        f"_log = Path({str(root / TRIPWIRE)!r})\n"
        f"_log.write_text((_log.read_text() if _log.exists() else '') + {folder!r} + '\\n')\n",
        encoding="utf-8",
    )
    directory.joinpath("plugin.py").write_text(
        _PLUGIN_PY.format(plugin_id=plugin_id, name=folder.title(), tool=tool, risk=risk),
        encoding="utf-8",
    )
    directory.joinpath("manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "package_id": package_id,
                "core_api_version": "1.0",
                "visibility": "public",
                "release_ring": "stable",
                "entrypoint": f"{folder}.plugin:create_plugin",
                "plugin": {
                    "schema_version": "1.0",
                    # Lets a test declare one id and implement another.
                    "plugin_id": declared_plugin_id or plugin_id,
                    "name": folder.title(),
                    "module_version": "1.0.0",
                    "tools": [{"name": tool, "risk": risk, "surface": "backend"}],
                },
            }
        ),
        encoding="utf-8",
    )
    return directory


def _tripwires(root: Path) -> set[str]:
    """Which plugin packages actually executed."""
    log = root / TRIPWIRE
    return set(log.read_text().split()) if log.exists() else set()


def test_a_package_on_disk_but_not_in_allow_is_never_imported(tmp_path, monkeypatch):
    _write_plugin(tmp_path, "wanted", package_id="example.wanted")
    _write_plugin(tmp_path, "uninvited", package_id="example.uninvited")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=["example.wanted"])

    assert _tripwires(tmp_path) == {"wanted"}
    assert set(result.plugins) == {"wanted"}
    uninvited = next(item for item in result.outcomes if item.folder == "uninvited")
    assert uninvited.loaded is False
    assert uninvited.code_ran is False
    assert "allowlist" in (uninvited.reason or "")


def test_an_empty_allowlist_loads_nothing_that_is_sitting_there(tmp_path, monkeypatch):
    _write_plugin(tmp_path, "wanted", package_id="example.wanted")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=[])

    assert _tripwires(tmp_path) == set()
    assert result.plugins == {}
    assert len(result.refused) == 1


def test_load_order_follows_the_allowlist_not_the_filesystem(tmp_path, monkeypatch):
    # Both claim the same tool name, so whichever loads first keeps it. Sorted by
    # filename "aaa" would win; the host asked for "zzz" first and should get it.
    _write_plugin(tmp_path, "aaa", package_id="example.aaa", tool="shared.tool")
    _write_plugin(tmp_path, "zzz", package_id="example.zzz", tool="shared.tool")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=["example.zzz", "example.aaa"])

    assert set(result.plugins) == {"zzz"}
    assert result.registry.tool_owner("shared.tool") == "zzz"
    loser = next(item for item in result.outcomes if item.folder == "aaa")
    assert "already owned by 'zzz'" in (loser.reason or "")
    assert loser.code_ran is False


def test_code_ran_separates_a_refusal_before_the_import_from_one_after(
    tmp_path, monkeypatch
):
    # Declares one plugin_id in the manifest and implements another, so it is
    # faultless on paper and can only be caught once there is an object to ask.
    _write_plugin(
        tmp_path,
        "liar",
        package_id="example.liar",
        plugin_id="liar",
        declared_plugin_id="liar_declared",
    )
    _write_plugin(tmp_path, "outsider", package_id="example.outsider")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=["example.liar"])

    liar = next(item for item in result.outcomes if item.folder == "liar")
    outsider = next(item for item in result.outcomes if item.folder == "outsider")

    assert liar.loaded is False
    assert liar.code_ran is True
    assert liar.stage == "imported, then rejected"
    assert "liar" in _tripwires(tmp_path)

    assert outsider.code_ran is False
    assert outsider.stage == "never imported"
    assert "outsider" not in _tripwires(tmp_path)


def test_a_refused_tool_risk_stops_the_plugin_before_it_is_imported(
    tmp_path, monkeypatch
):
    _write_plugin(tmp_path, "eraser", package_id="example.eraser", risk="destructive")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(
        tmp_path,
        allow=["example.eraser"],
        policy=Policy(refuse_tool_risks=frozenset({ToolRisk.DESTRUCTIVE})),
    )

    assert _tripwires(tmp_path) == set()
    outcome = result.outcomes[0]
    assert outcome.loaded is False
    assert outcome.code_ran is False
    assert "risk 'destructive'" in (outcome.reason or "")


def test_the_same_plugin_loads_when_the_host_does_not_refuse_that_risk(
    tmp_path, monkeypatch
):
    # Without this, the test above would pass even if refuse_tool_risks did
    # nothing and the plugin was broken for some unrelated reason.
    _write_plugin(tmp_path, "eraser", package_id="example.eraser", risk="destructive")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=["example.eraser"])

    assert set(result.plugins) == {"eraser"}


def test_the_report_says_how_many_were_stopped_before_running(tmp_path, monkeypatch):
    _write_plugin(tmp_path, "good", package_id="example.good")
    _write_plugin(tmp_path, "unlisted", package_id="example.unlisted")
    monkeypatch.syspath_prepend(str(tmp_path))

    text = load_plugins(tmp_path, allow=["example.good"]).text()

    assert "LOADED" in text
    assert "REFUSED" in text
    assert "never imported" in text
    assert "1 loaded, 1 refused" in text
    assert "1 of the 1 stopped before any of their code ran" in text


def test_a_directory_that_is_not_importable_says_so_instead_of_refusing_everything(
    tmp_path,
):
    # preflight never edits sys.path. Without this guard the host gets a pile of
    # "no file on disk" refusals that read like a preflight bug.
    _write_plugin(tmp_path, "widget", package_id="example.widget")

    with pytest.raises(RuntimeError, match="not on sys.path"):
        load_plugins(tmp_path, allow=["example.widget"])


def test_a_missing_directory_is_an_error_not_an_empty_report(tmp_path):
    with pytest.raises(NotADirectoryError):
        load_plugins(tmp_path / "nowhere", allow=[])


def test_the_loaded_plugin_is_callable_and_owns_its_tool(tmp_path, monkeypatch):
    _write_plugin(tmp_path, "widget", package_id="example.widget", tool="widget.do")
    monkeypatch.syspath_prepend(str(tmp_path))

    result = load_plugins(tmp_path, allow=["example.widget"])

    assert result.get("widget").hello() == "hello from widget"
    assert result.registry.tool_owner("widget.do") == "widget"
    assert result.outcomes[0].tool_count == 1
