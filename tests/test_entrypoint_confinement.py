"""The entrypoint string must point inside the trusted root, or nothing runs.

A manifest file is confined to ``trusted_root`` by ``load_manifest_file``. The
entrypoint *inside* that manifest is a separate question: the model validates its
shape, not its location, so a manifest sitting in the trusted root could name any
importable module on ``sys.path``.

Every test here drives the real ``_import_entrypoint``. Injecting a fake importer
would exercise the seam instead of the check and prove nothing. Where an
out-of-tree module is involved, it writes a tripwire file at import time and the
test asserts the tripwire never fired -- the point is not that an error was
raised, it is that the code never ran.

Note what the tests have to do for themselves: ``monkeypatch.syspath_prepend``.
preflight does not touch ``sys.path``; making a plugin directory importable is
the host's job.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from preflight import PluginRejected, public_build
from preflight import registry as registry_module


@pytest.fixture(autouse=True)
def _forget_modules_imported_by_the_test():
    """Keep one test's probe modules out of the next test's ``sys.modules``."""
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        del sys.modules[name]


def _manifest_payload(
    *,
    package_id: str,
    plugin_id: str,
    entrypoint: str,
) -> dict:
    return {
        "package_id": package_id,
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": entrypoint,
        "plugin": {
            "plugin_id": plugin_id,
            "name": "Confinement Probe",
            "module_version": "1.0.0",
            "tools": [],
        },
    }


def _write_manifest(root: Path, payload: dict) -> Path:
    path = root / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _plugin_source(plugin_manifest: dict) -> str:
    """A minimal well-behaved plugin: it reports the manifest it declared."""
    return (
        "import json\n"
        "from preflight import PluginManifest\n"
        f"_MANIFEST = json.loads(r'''{json.dumps(plugin_manifest)}''')\n"
        "class ConfinedPlugin:\n"
        "    def __init__(self):\n"
        "        self.manifest = PluginManifest.model_validate(_MANIFEST)\n"
        "def create_plugin():\n"
        "    return ConfinedPlugin()\n"
    )


def _tripwire_source(tripwire: Path, extra: str = "") -> str:
    """A module that records the fact that it was imported."""
    return (
        "from pathlib import Path\n"
        f"Path({str(tripwire)!r}).write_text('executed', encoding='utf-8')\n"
        f"{extra}"
    )


def test_a_plugin_inside_the_trusted_root_loads(tmp_path: Path, monkeypatch):
    root = tmp_path / "plugins"
    root.mkdir()
    payload = _manifest_payload(
        package_id="example.confined",
        plugin_id="confined",
        entrypoint="confined_plugin:create_plugin",
    )
    manifest_path = _write_manifest(root, payload)
    (root / "confined_plugin.py").write_text(
        _plugin_source(payload["plugin"]), encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(root))

    registry = public_build(allowed_package_ids={"example.confined"})
    registered = registry.load_manifest_file(manifest_path, trusted_root=root)

    assert registry.get("confined") is registered.instance
    assert registered.instance.manifest.plugin_id == "confined"


def test_an_entrypoint_outside_the_trusted_root_never_executes(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "plugins"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    tripwire = tmp_path / "tripwire.txt"
    (elsewhere / "outsider.py").write_text(
        _tripwire_source(tripwire, "def create_plugin():\n    return None\n"),
        encoding="utf-8",
    )
    manifest_path = _write_manifest(
        root,
        _manifest_payload(
            package_id="example.outsider",
            plugin_id="outsider",
            entrypoint="outsider:create_plugin",
        ),
    )
    monkeypatch.syspath_prepend(str(elsewhere))

    registry = public_build(allowed_package_ids={"example.outsider"})
    with pytest.raises(PluginRejected, match="outside the trusted plugin root"):
        registry.load_manifest_file(manifest_path, trusted_root=root)

    assert tripwire.exists() is False
    assert "outsider" not in sys.modules
    assert registry.available() == ()


@pytest.mark.parametrize(
    ("entrypoint", "reason"),
    [
        # A plain stdlib module resolves to a real file; it fails the path check.
        ("json:loads", "outside the trusted plugin root"),
        # `os` is frozen into the interpreter from 3.11 on, so it has no file to
        # compare and fails closed on the other branch instead. Both are refusals.
        ("os.path:join", "has no file on disk"),
    ],
)
def test_an_entrypoint_naming_a_standard_library_module_is_refused(
    tmp_path: Path, entrypoint: str, reason: str
):
    root = tmp_path / "plugins"
    root.mkdir()
    manifest_path = _write_manifest(
        root,
        _manifest_payload(
            package_id="example.stdlib",
            plugin_id="stdlib.probe",
            entrypoint=entrypoint,
        ),
    )

    registry = public_build(allowed_package_ids={"example.stdlib"})
    with pytest.raises(PluginRejected, match=reason):
        registry.load_manifest_file(manifest_path, trusted_root=root)

    assert registry.available() == ()


def test_an_entrypoint_naming_a_builtin_module_is_refused(tmp_path: Path):
    """The fail-closed case: no file on disk means no way to prove it is in-tree."""
    root = tmp_path / "plugins"
    root.mkdir()
    manifest_path = _write_manifest(
        root,
        _manifest_payload(
            package_id="example.builtin",
            plugin_id="builtin.probe",
            entrypoint="sys:path",
        ),
    )

    registry = public_build(allowed_package_ids={"example.builtin"})
    with pytest.raises(PluginRejected, match="has no file on disk"):
        registry.load_manifest_file(manifest_path, trusted_root=root)

    assert registry.available() == ()


def test_a_dotted_entrypoint_cannot_execute_an_out_of_tree_parent_package(
    tmp_path: Path, monkeypatch
):
    """``find_spec("a.b")`` imports ``a``. So ``a`` is checked before ``a.b`` is asked for."""
    root = tmp_path / "plugins"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere"
    package_dir = elsewhere / "outerpkg"
    package_dir.mkdir(parents=True)
    tripwire = tmp_path / "parent-tripwire.txt"
    (package_dir / "__init__.py").write_text(
        _tripwire_source(tripwire), encoding="utf-8"
    )
    (package_dir / "inner.py").write_text(
        "def create_plugin():\n    return None\n", encoding="utf-8"
    )
    manifest_path = _write_manifest(
        root,
        _manifest_payload(
            package_id="example.dotted",
            plugin_id="dotted.probe",
            entrypoint="outerpkg.inner:create_plugin",
        ),
    )
    monkeypatch.syspath_prepend(str(elsewhere))

    registry = public_build(allowed_package_ids={"example.dotted"})
    with pytest.raises(PluginRejected, match="outside the trusted plugin root"):
        registry.load_manifest_file(manifest_path, trusted_root=root)

    assert tripwire.exists() is False
    assert "outerpkg" not in sys.modules


def test_a_module_whose_file_changes_after_resolution_is_still_refused(
    tmp_path: Path, monkeypatch
):
    """Covers the post-import re-check.

    Resolution and import are two steps with global mutable state in between, so
    the check is repeated on the module that actually loaded. Here resolution is
    forced to lie -- every name reports a file inside the trusted root -- and the
    second check has to be the thing that catches it.
    """
    root = tmp_path / "plugins"
    root.mkdir()
    manifest_path = _write_manifest(
        root,
        _manifest_payload(
            package_id="example.moved",
            plugin_id="moved.probe",
            entrypoint="os.path:join",
        ),
    )
    monkeypatch.setattr(
        registry_module, "_module_file", lambda name: root / f"{name}.py"
    )

    registry = public_build(allowed_package_ids={"example.moved"})
    with pytest.raises(PluginRejected, match="was imported from"):
        registry.load_manifest_file(manifest_path, trusted_root=root)

    assert registry.available() == ()
