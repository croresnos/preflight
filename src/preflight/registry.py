"""A fail-closed plugin registry: every decision happens before the import.

Importing a Python module runs it. Module-level statements execute the moment
the import resolves, so a loader that imports first and inspects afterwards has
already given the plugin its turn. This registry inverts that order. It reads
the manifest file, validates it, applies the build's policy, and checks for name
collisions -- all against inert JSON -- and only then calls the loader.

This is not a sandbox. Once a plugin is imported it is ordinary Python with the
full run of the process. preflight decides *whether* to import, and has no power
after that.
"""

from __future__ import annotations

import importlib
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable

from pydantic import ValidationError

from preflight.manifest import (
    Platform,
    Plugin,
    PluginManifest,
    PluginPackageManifest,
    ReleaseRing,
    Tool,
    Visibility,
)


class Edition(str, Enum):
    """What a build is willing to accept."""

    PUBLIC = "public"
    INTERNAL = "internal"
    DEVELOPMENT = "development"


class PluginRejected(RuntimeError):
    """A plugin was refused. The registry was not modified."""


PluginLoader = Callable[[], object]
EntrypointImporter = Callable[[str], object]


@dataclass(frozen=True)
class _EditionPolicy:
    visibilities: frozenset[Visibility]
    rings: frozenset[ReleaseRing]


#: The whole tier policy, in one table. A public build takes public plugins from
#: the stable ring and nothing else; each edition below it widens both axes.
_EDITION_POLICY: dict[Edition, _EditionPolicy] = {
    Edition.PUBLIC: _EditionPolicy(
        visibilities=frozenset({Visibility.PUBLIC}),
        rings=frozenset({ReleaseRing.STABLE}),
    ),
    Edition.INTERNAL: _EditionPolicy(
        visibilities=frozenset({Visibility.PUBLIC, Visibility.INTERNAL}),
        rings=frozenset({ReleaseRing.STABLE, ReleaseRing.BETA}),
    ),
    Edition.DEVELOPMENT: _EditionPolicy(
        visibilities=frozenset(Visibility),
        rings=frozenset(ReleaseRing),
    ),
}

_HOST_PLATFORMS = {
    "win32": Platform.WINDOWS,
    "darwin": Platform.MACOS,
    "linux": Platform.LINUX,
}


def _host_platform() -> Platform:
    try:
        return _HOST_PLATFORMS[sys.platform]
    except KeyError:
        raise RuntimeError(
            f"unrecognised host platform '{sys.platform}'; pass platform= explicitly"
        ) from None


@dataclass(frozen=True)
class RegisteredPlugin:
    package: PluginPackageManifest
    instance: Plugin
    origin: str


def _import_entrypoint(entrypoint: str) -> object:
    module_name, attribute = entrypoint.split(":", 1)
    module = importlib.import_module(module_name)
    exported = getattr(module, attribute)
    return exported() if callable(exported) else exported


class PluginRegistry:
    """Registers compatible plugins without crossing edition boundaries."""

    MAX_MANIFEST_BYTES = 256 * 1024

    def __init__(
        self,
        *,
        edition: Edition,
        allowed_package_ids: Iterable[str],
        platform: Platform | str | None = None,
    ) -> None:
        self.edition = Edition(edition)
        self.platform = Platform(platform) if platform is not None else _host_platform()
        self.allowed_package_ids = frozenset(allowed_package_ids)
        self._by_plugin: dict[str, RegisteredPlugin] = {}
        self._tool_owners: dict[str, str] = {}
        self._tools: dict[str, Tool] = {}

    def available(self) -> tuple[PluginManifest, ...]:
        return tuple(
            registered.package.plugin.model_copy(deep=True)
            for registered in self._by_plugin.values()
        )

    def get(self, plugin_id: str) -> Plugin | None:
        """Return the live object of one active plugin, or ``None``."""
        registered = self._by_plugin.get(plugin_id)
        return registered.instance if registered else None

    def manifest(self, plugin_id: str) -> PluginManifest | None:
        """Return a defensive copy of one active plugin's typed manifest."""
        registered = self._by_plugin.get(plugin_id)
        if registered is None:
            return None
        return registered.package.plugin.model_copy(deep=True)

    def tool_owner(self, tool_name: str) -> str | None:
        """Return the active plugin that exclusively owns a tool name."""
        return self._tool_owners.get(tool_name)

    def tool(self, tool_name: str) -> Tool | None:
        """Return a defensive copy of an active plugin's tool declaration."""
        declared = self._tools.get(tool_name)
        return declared.model_copy(deep=True) if declared is not None else None

    def register(
        self,
        package: PluginPackageManifest,
        loader: PluginLoader,
        *,
        origin: str,
    ) -> RegisteredPlugin:
        """Validate policy and declared collisions before executing ``loader``."""
        try:
            package = PluginPackageManifest.model_validate(
                package.model_dump(mode="json")
            )
        except (AttributeError, ValidationError) as exc:
            raise PluginRejected(
                f"invalid plugin package manifest from {origin}: {exc}"
            ) from exc
        self._validate_preload_policy(package)
        plugin_id = package.plugin.plugin_id
        if plugin_id in self._by_plugin:
            raise PluginRejected(f"plugin '{plugin_id}' is already registered")
        declared_tools: set[str] = set()
        for tool in package.plugin.tools:
            if tool.name in declared_tools:
                raise PluginRejected(
                    f"duplicate tool name '{tool.name}' in package '{package.package_id}'"
                )
            declared_tools.add(tool.name)
            owner = self._tool_owners.get(tool.name)
            if owner:
                raise PluginRejected(
                    f"tool name collision: '{tool.name}' is already owned by '{owner}'"
                )

        # Nothing above this line has run a line of the plugin's code.
        try:
            instance = loader()
        except Exception as exc:
            raise PluginRejected(
                f"failed to load plugin package '{package.package_id}' from {origin}: {exc}"
            ) from exc

        if not isinstance(instance, Plugin):
            raise PluginRejected(
                f"entrypoint for '{package.package_id}' does not implement Plugin"
            )
        try:
            runtime_manifest = PluginManifest.model_validate(instance.manifest)
        except ValidationError as exc:
            raise PluginRejected(
                f"runtime manifest for '{package.package_id}' is invalid: {exc}"
            ) from exc
        if runtime_manifest != package.plugin:
            raise PluginRejected(
                f"runtime manifest for '{package.package_id}' does not match "
                "its validated package manifest"
            )

        registered = RegisteredPlugin(
            package=package,
            instance=instance,
            origin=origin,
        )
        self._by_plugin[plugin_id] = registered
        for tool in package.plugin.tools:
            self._tool_owners[tool.name] = plugin_id
            self._tools[tool.name] = tool.model_copy(deep=True)
        return registered

    def load_manifest_file(
        self,
        manifest_path: Path | str,
        *,
        trusted_root: Path | str,
        importer: EntrypointImporter = _import_entrypoint,
    ) -> RegisteredPlugin:
        """Load one manifest confined to ``trusted_root`` and then its entry point."""
        path = Path(manifest_path).resolve()
        root = Path(trusted_root).resolve()
        if not path.is_relative_to(root):
            raise PluginRejected(
                f"plugin manifest must be inside the trusted plugin root '{root}'"
            )
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PluginRejected(f"cannot read plugin manifest '{path}': {exc}") from exc
        if size > self.MAX_MANIFEST_BYTES:
            raise PluginRejected(
                f"plugin manifest '{path}' exceeds {self.MAX_MANIFEST_BYTES} bytes"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            package = PluginPackageManifest.model_validate(payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
            raise PluginRejected(f"invalid plugin manifest '{path}': {exc}") from exc

        return self.register(
            package,
            lambda: importer(package.entrypoint),
            origin=str(path),
        )

    def _validate_preload_policy(self, package: PluginPackageManifest) -> None:
        if package.package_id not in self.allowed_package_ids:
            raise PluginRejected(
                f"package '{package.package_id}' is not in the explicit build allowlist"
            )
        if (
            package.plugin.supported_platforms
            and self.platform not in package.plugin.supported_platforms
        ):
            raise PluginRejected(
                f"package '{package.package_id}' does not support platform "
                f"'{self.platform.value}'"
            )

        policy = _EDITION_POLICY[self.edition]
        if package.visibility not in policy.visibilities:
            raise PluginRejected(
                f"{self.edition.value} build cannot load '{package.package_id}' "
                f"with visibility '{package.visibility.value}'"
            )
        if package.release_ring not in policy.rings:
            raise PluginRejected(
                f"{self.edition.value} build cannot load '{package.package_id}' "
                f"from the '{package.release_ring.value}' release ring"
            )


def public_build(
    *,
    allowed_package_ids: Iterable[str] = (),
    platform: Platform | str | None = None,
) -> PluginRegistry:
    """A registry that accepts public plugins from the stable ring, and nothing else."""
    return PluginRegistry(
        edition=Edition.PUBLIC,
        allowed_package_ids=allowed_package_ids,
        platform=platform,
    )


def internal_build(
    *,
    allowed_package_ids: Iterable[str] = (),
    platform: Platform | str | None = None,
) -> PluginRegistry:
    """A registry that additionally accepts internal plugins from the beta ring."""
    return PluginRegistry(
        edition=Edition.INTERNAL,
        allowed_package_ids=allowed_package_ids,
        platform=platform,
    )


def development_build(
    *,
    allowed_package_ids: Iterable[str] = (),
    platform: Platform | str | None = None,
) -> PluginRegistry:
    """A registry that accepts every visibility and ring. Never ship this one."""
    return PluginRegistry(
        edition=Edition.DEVELOPMENT,
        allowed_package_ids=allowed_package_ids,
        platform=platform,
    )
