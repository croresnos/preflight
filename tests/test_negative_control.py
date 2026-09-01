"""Proof that the confinement check is what stops the import.

A security test that passes with *and* without the fix proves nothing. This file
runs one scenario twice through the same harness, changing exactly one thing --
which importer the registry is handed -- and asserts the two outcomes differ.

``_unconfined_importer`` below is a copy of what this loader did before the
confinement check existed. It is not reachable from the library; it exists so the
difference can be measured rather than asserted. The interesting result is not
that the confined importer refuses the plugin. It is *when* the unconfined one
does: it refuses it too, on a later and unrelated ground, having already run the
plugin's top-level code. Raising an exception is not the same as failing closed.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from preflight import PluginRejected, public_build
from preflight.registry import _import_entrypoint


def _unconfined_importer(entrypoint: str, _trusted_root: Path) -> object:
    """The pre-fix importer, kept only as the control condition.

    The manifest is confined to the trusted root before this is reached. The
    entrypoint *string* inside it is confined to nothing, so the module name goes
    straight to the import machinery.
    """
    module_name, attribute = entrypoint.split(":", 1)
    module = importlib.import_module(module_name)
    exported = getattr(module, attribute)
    return exported() if callable(exported) else exported


@pytest.fixture(autouse=True)
def _forget_modules_imported_by_the_test():
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        del sys.modules[name]


def _run_scenario(tmp_path: Path, monkeypatch, *, importer, label: str):
    """Point a manifest inside the trusted root at a module outside it.

    Returns whether the out-of-tree module executed, and how the load was
    refused. The plugin is bad on two independent counts -- it lives outside the
    trusted root, and its factory returns something that is not a plugin -- which
    is what lets the two importers be told apart by which objection lands first.
    """
    case = tmp_path / label
    root = case / "plugins"
    elsewhere = case / "elsewhere"
    root.mkdir(parents=True)
    elsewhere.mkdir()

    tripwire = case / "tripwire.txt"
    module_name = f"outsider_{label}"
    (elsewhere / f"{module_name}.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(tripwire)!r}).write_text('executed', encoding='utf-8')\n"
        "def create_plugin():\n"
        "    return None\n",
        encoding="utf-8",
    )

    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "package_id": "example.outsider",
                "core_api_version": "1.0",
                "visibility": "public",
                "release_ring": "stable",
                "entrypoint": f"{module_name}:create_plugin",
                "plugin": {
                    "plugin_id": "outsider",
                    "name": "Confinement Probe",
                    "module_version": "1.0.0",
                    "tools": [],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(elsewhere))

    registry = public_build(allowed_package_ids={"example.outsider"})
    with pytest.raises(PluginRejected) as refusal:
        registry.load_manifest_file(manifest_path, trusted_root=root, importer=importer)

    assert registry.available() == ()
    return tripwire.exists(), str(refusal.value)


def test_the_confinement_check_is_what_stops_the_out_of_tree_import(
    tmp_path: Path, monkeypatch
):
    without_fix_executed, without_fix_reason = _run_scenario(
        tmp_path, monkeypatch, importer=_unconfined_importer, label="control"
    )
    with_fix_executed, with_fix_reason = _run_scenario(
        tmp_path, monkeypatch, importer=_import_entrypoint, label="confined"
    )

    # The control has to actually fail, or the test below is measuring nothing.
    assert without_fix_executed is True, (
        "negative control did not reproduce the hole: the unconfined importer was "
        "expected to execute the out-of-tree module"
    )
    # And it failed late. The refusal is about the object that came back, which
    # means the module had already been imported to produce one.
    assert "does not implement Plugin" in without_fix_reason

    assert with_fix_executed is False
    assert "outside the trusted plugin root" in with_fix_reason
