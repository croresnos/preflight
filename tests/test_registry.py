"""Plugin ABI and loading-boundary tests.

The assertion that matters in this file is ``assert loaded is False``. It does
not say "an error was raised" -- it says the plugin's code never ran. Every
rejection path is tested that way on purpose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from preflight import (
    Edition,
    Plugin,
    PluginManifest,
    PluginPackageManifest,
    PluginRegistry,
    PluginRejected,
    Tool,
    ToolRisk,
    public_build,
)


def _package(
    *,
    package_id: str = "example.mail.test",
    plugin_id: str = "mail.test",
    visibility: str = "public",
    release_ring: str = "stable",
    entrypoint: str = "example_mail.plugin:plugin",
) -> PluginPackageManifest:
    return PluginPackageManifest.model_validate(
        {
            "package_id": package_id,
            "core_api_version": "1.0",
            "visibility": visibility,
            "release_ring": release_ring,
            "entrypoint": entrypoint,
            "plugin": {
                "plugin_id": plugin_id,
                "name": "Test Mail",
                "module_version": "1.0.0",
                "supported_platforms": ["windows"],
                "tools": [{"name": f"{plugin_id}.search", "risk": "read"}],
            },
        }
    )


class _Plugin:
    def __init__(self, manifest: PluginManifest):
        self.manifest = manifest


def test_a_runtime_mismatch_names_the_field_and_both_values():
    """ "Does not match" alone leaves somebody diffing two files by eye.

    This is the refusal a person meets when a version was bumped in the code and
    not in the manifest, which is the ordinary way to reach it and the one the
    `preflight try` exercises stage deliberately. Unqualified, its next step is a
    manual comparison of a manifest against a source file; the two objects being
    compared are both in hand at the point of refusal, so it can do better.
    """
    package = _package()
    drifted = _Plugin(package.plugin.model_copy(update={"module_version": "2.0.0"}))
    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )

    with pytest.raises(PluginRejected) as refusal:
        registry.register(package, lambda: drifted, origin="built-in")

    message = str(refusal.value)
    assert "does not match its validated package manifest" in message
    assert "module_version: manifest says '1.0.0', plugin reports '2.0.0'" in message


def test_a_runtime_mismatch_in_the_tool_list_names_the_tool():
    """The tools case, which is the one with security consequences.

    A host builds its permission prompts from `registry.available()`, so a
    plugin that declares two tools and reports three is trying to be advertised
    for something the gate never saw. Rendering both whole tool lists to show it
    would bury the answer in schema and truncate away the appended entry, so the
    difference is reported as membership: which names appeared, went missing, or
    changed while keeping their name.
    """
    package = _package()
    extra = Tool.model_validate({"name": "mail.test.purge", "risk": "destructive"})
    smuggled = _Plugin(
        package.plugin.model_copy(update={"tools": [*package.plugin.tools, extra]})
    )
    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )

    with pytest.raises(PluginRejected) as refusal:
        registry.register(package, lambda: smuggled, origin="built-in")

    assert "tools -- undeclared in the manifest: mail.test.purge" in str(refusal.value)


def test_a_tool_that_keeps_its_name_and_changes_its_risk_is_named_too():
    """Neither list gains nor loses an entry, and this is the dangerous shape.

    `read` on paper and `destructive` once loaded is the mismatch a membership
    diff alone would report as "tools differ" -- the same names, both sides.
    """
    package = _package()
    louder = package.plugin.tools[0].model_copy(update={"risk": ToolRisk.DESTRUCTIVE})
    lying = _Plugin(package.plugin.model_copy(update={"tools": [louder]}))
    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )

    with pytest.raises(PluginRejected) as refusal:
        registry.register(package, lambda: lying, origin="built-in")

    assert "tools -- declared differently: mail.test.search" in str(refusal.value)


def test_plugin_package_manifest_is_closed_and_has_a_strict_entrypoint():
    package = _package()

    assert package.schema_version == "1.0"
    assert package.plugin.plugin_id == "mail.test"

    # A bare module is the second legal shape: it waives the runtime-manifest
    # comparison rather than failing it. See `self_reports_manifest`.
    assert _package(entrypoint="example_mail.plugin").self_reports_manifest is False
    assert package.self_reports_manifest is True

    for malformed in (
        "example_mail.plugin:",  # a colon promising an attribute that is not there
        ":create_plugin",  # an attribute with no module to find it in
        "example_mail.plugin:_private",  # a private name is not an entrypoint
        "example_mail.plugin:create:extra",  # attribute is not an identifier
        "example_mail..plugin",  # an empty path segment
    ):
        with pytest.raises(ValidationError):
            _package(entrypoint=malformed)

    with pytest.raises(ValidationError):
        PluginPackageManifest.model_validate(
            {**package.model_dump(mode="json"), "arbitrary_code": "exec('no')"}
        )

    with pytest.raises(ValidationError):
        _package(visibility="restricted", release_ring="stable")


@pytest.mark.parametrize(
    ("visibility", "release_ring"),
    [("restricted", "experimental"), ("public", "beta")],
)
def test_public_registry_rejects_non_public_modules_before_loading(
    visibility, release_ring
):
    package = _package(visibility=visibility, release_ring=release_ring)
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(package.plugin)

    registry = PluginRegistry(
        edition=Edition.PUBLIC,
        platform="windows",
        allowed_package_ids={package.package_id},
    )

    with pytest.raises(PluginRejected, match="public build"):
        registry.register(package, loader, origin="test")

    assert loaded is False
    assert registry.available() == ()


def test_a_plugin_that_does_not_support_the_host_platform_is_refused_before_loading():
    package = _package()  # declares windows and nothing else
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(package.plugin)

    registry = public_build(allowed_package_ids={package.package_id}, platform="linux")
    with pytest.raises(PluginRejected, match="does not support platform 'linux'"):
        registry.register(package, loader, origin="test")

    assert loaded is False
    assert registry.available() == ()


def test_registry_revalidates_mutated_manifests_before_loading():
    package = _package()
    package.plugin.plugin_id = ""
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(package.plugin)

    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )
    with pytest.raises(PluginRejected, match="invalid plugin package manifest"):
        registry.register(package, loader, origin="built-in")

    assert loaded is False


def test_public_registry_requires_an_explicit_build_allowlist_before_loading():
    package = _package()
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(package.plugin)

    registry = public_build(allowed_package_ids=set(), platform="windows")

    with pytest.raises(PluginRejected, match="build allowlist"):
        registry.register(package, loader, origin="test")

    assert loaded is False


def test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions():
    package = _package()
    plugin = _Plugin(package.plugin)
    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )

    registered = registry.register(package, lambda: plugin, origin="built-in")

    assert isinstance(registered.instance, Plugin)
    assert registry.get("mail.test") is plugin
    assert registry.available() == (package.plugin,)
    assert registry.tool_owner("mail.test.search") == "mail.test"
    declared_tool = registry.tool("mail.test.search")
    assert declared_tool is not None
    assert declared_tool.risk.value == "read"
    declared_tool.name = "mutated.outside.registry"
    assert registry.tool("mail.test.search").name == "mail.test.search"
    assert registry.manifest("mail.test").plugin_id == "mail.test"
    listed_manifest = registry.available()[0]
    listed_manifest.plugin_id = "mutated.outside.registry"
    assert registry.manifest("mail.test").plugin_id == "mail.test"

    mismatched = _Plugin(package.plugin.model_copy(update={"plugin_id": "mail.wrong"}))
    other_package = _package(package_id="example.mail.other", plugin_id="mail.other")
    registry_with_allowlist = public_build(
        allowed_package_ids={other_package.package_id}, platform="windows"
    )
    with pytest.raises(PluginRejected, match="does not match"):
        registry_with_allowlist.register(
            other_package, lambda: mismatched, origin="built-in"
        )

    collision = _package(package_id="example.calendar.test", plugin_id="calendar.test")
    collision.plugin.tools[0].name = package.plugin.tools[0].name
    registry_with_collision_allowlist = public_build(
        allowed_package_ids={package.package_id, collision.package_id},
        platform="windows",
    )
    registry_with_collision_allowlist.register(
        package, lambda: plugin, origin="built-in"
    )
    with pytest.raises(PluginRejected, match="tool name collision"):
        registry_with_collision_allowlist.register(
            collision, lambda: _Plugin(collision.plugin), origin="built-in"
        )


def test_duplicate_declared_tool_names_are_rejected_before_loading():
    package = _package()
    package.plugin.tools.append(package.plugin.tools[0].model_copy())
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(package.plugin)

    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )
    with pytest.raises(PluginRejected, match="duplicate tool name"):
        registry.register(package, loader, origin="built-in")

    assert loaded is False


def test_a_second_package_claiming_a_registered_plugin_id_is_refused_before_loading():
    first = _package()
    second = _package(package_id="example.mail.clone")
    # Give it a distinct tool name so the plugin_id check is unambiguously the
    # thing that fires, rather than the collision check downstream of it.
    second.plugin.tools[0].name = "mail.clone.search"
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(second.plugin)

    registry = public_build(
        allowed_package_ids={first.package_id, second.package_id},
        platform="windows",
    )
    registry.register(first, lambda: _Plugin(first.plugin), origin="built-in")

    with pytest.raises(PluginRejected, match="is already registered"):
        registry.register(second, loader, origin="test")

    assert loaded is False
    assert len(registry.available()) == 1


def test_a_second_plugin_claiming_a_registered_package_id_is_refused_before_loading():
    first = _package()
    second = _package(plugin_id="mail.clone")
    second.plugin.tools[0].name = "mail.clone.search"
    loaded = False

    def loader():
        nonlocal loaded
        loaded = True
        return _Plugin(second.plugin)

    registry = public_build(allowed_package_ids={first.package_id}, platform="windows")
    registry.register(first, lambda: _Plugin(first.plugin), origin="built-in")

    with pytest.raises(PluginRejected, match="package .* already registered"):
        registry.register(second, loader, origin="test")

    assert loaded is False
    assert len(registry.available()) == 1


def test_an_entrypoint_returning_something_other_than_a_plugin_is_refused():
    package = _package()
    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )

    with pytest.raises(PluginRejected, match="does not implement Plugin"):
        registry.register(package, lambda: object(), origin="test")

    assert registry.available() == ()
    assert registry.tool_owner("mail.test.search") is None


def test_manifest_file_is_confined_and_validated_before_import(tmp_path: Path):
    trusted_root = tmp_path / "plugins"
    package_root = trusted_root / "mail"
    package_root.mkdir(parents=True)
    package = _package()
    manifest_path = package_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(package.model_dump(mode="json")), encoding="utf-8"
    )
    imports: list[str] = []

    def importer(entrypoint: str, _trusted_root: Path):
        imports.append(entrypoint)
        return _Plugin(package.plugin)

    registry = public_build(
        allowed_package_ids={package.package_id}, platform="windows"
    )
    registry.load_manifest_file(
        manifest_path, trusted_root=trusted_root, importer=importer
    )

    assert imports == [package.entrypoint]

    outside = tmp_path / "outside.json"
    outside.write_text(manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(PluginRejected, match="trusted plugin root"):
        registry.load_manifest_file(
            outside, trusted_root=trusted_root, importer=importer
        )


def test_an_oversized_manifest_is_refused_before_it_is_even_parsed(tmp_path: Path):
    trusted_root = tmp_path / "plugins"
    trusted_root.mkdir()
    manifest_path = trusted_root / "manifest.json"
    # Deliberately not JSON. If the size cap fires first the refusal names the
    # cap; if it did not, the refusal would be a parse error instead, and this
    # test would be measuring the wrong check.
    manifest_path.write_text(
        "x" * (PluginRegistry.MAX_MANIFEST_BYTES + 1), encoding="utf-8"
    )
    imported = False

    def importer(_entrypoint: str, _trusted_root: Path):
        nonlocal imported
        imported = True
        raise AssertionError("unreachable")

    registry = public_build(
        allowed_package_ids={"example.mail.test"}, platform="windows"
    )
    with pytest.raises(PluginRejected, match="exceeds 262144 bytes"):
        registry.load_manifest_file(
            manifest_path, trusted_root=trusted_root, importer=importer
        )

    assert imported is False


def test_invalid_or_restricted_manifest_never_reaches_the_importer(tmp_path: Path):
    trusted_root = tmp_path / "plugins"
    trusted_root.mkdir()
    restricted_package = _package(visibility="restricted", release_ring="experimental")
    manifest_path = trusted_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(restricted_package.model_dump(mode="json")), encoding="utf-8"
    )
    imported = False

    def importer(_entrypoint: str, _trusted_root: Path):
        nonlocal imported
        imported = True
        return _Plugin(restricted_package.plugin)

    registry = public_build(
        allowed_package_ids={restricted_package.package_id}, platform="windows"
    )
    with pytest.raises(PluginRejected, match="public build"):
        registry.load_manifest_file(
            manifest_path, trusted_root=trusted_root, importer=importer
        )

    assert imported is False
