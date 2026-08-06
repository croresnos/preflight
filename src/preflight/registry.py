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
import importlib.util
import json
import os
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
    ToolRisk,
    Visibility,
    manifest_differences,
    manifest_error_message,
)


class Edition(str, Enum):
    """What a build is willing to accept."""

    PUBLIC = "public"
    INTERNAL = "internal"
    DEVELOPMENT = "development"


class PluginRejected(RuntimeError):
    """A plugin was refused. The registry was not modified."""


PluginLoader = Callable[[], object]
EntrypointImporter = Callable[[str, Path], object]


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


def host_platform() -> Platform:
    """The platform a default policy resolves to: the one this process is on.

    Public because three places need the same answer -- the registry's default,
    ``preflight check``, and the settings display -- and three copies of a
    ``sys.platform`` mapping is three chances to disagree about what "windows"
    means.
    """
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


def preload_refusals(
    package: PluginPackageManifest,
    *,
    platform: Platform,
    edition: Edition = Edition.PUBLIC,
    refuse_tool_risks: Iterable[ToolRisk | str] = (),
) -> tuple[str, ...]:
    """Every reason this package would be refused before anything is imported.

    Pure, and decided from the manifest alone. Two callers need this answer and
    they must not be able to disagree: :meth:`PluginRegistry._validate_preload_policy`
    raises on the first entry, and ``preflight check`` -- which imports nothing at
    all -- reports every entry so a person can see the whole list at once.

    A single source of truth is the point. ``check`` previously judged only the
    declared risks, so a package the gate would refuse for its platform or its
    release ring passed the command and exited zero. The command is recommended
    for CI precisely to catch that, and it could not.

    The allowlist is deliberately absent. It is a host's decision and there is no
    host at a terminal, so it stays inline in the registry rather than becoming a
    parameter that ``check`` would always have to pass nothing for.
    """
    refused = frozenset(ToolRisk(risk) for risk in refuse_tool_risks)
    reasons: list[str] = []

    if package.plugin.supported_platforms and platform not in package.plugin.supported_platforms:
        reasons.append(
            f"package '{package.package_id}' does not support platform "
            f"'{platform.value}'"
        )

    # A declared risk the host has said it will not accept. This is the one place
    # preflight acts on ToolRisk, and only because a host asked it to.
    for tool in package.plugin.tools:
        if tool.risk in refused:
            reasons.append(
                f"package '{package.package_id}' declares tool '{tool.name}' with "
                f"risk '{tool.risk.value}', which this host refuses"
            )

    policy = _EDITION_POLICY[edition]
    if package.visibility not in policy.visibilities:
        reasons.append(
            f"{edition.value} build cannot load '{package.package_id}' "
            f"with visibility '{package.visibility.value}'"
        )
    if package.release_ring not in policy.rings:
        reasons.append(
            f"{edition.value} build cannot load '{package.package_id}' "
            f"from the '{package.release_ring.value}' release ring"
        )
    return tuple(reasons)


def _import_chain(module_name: str) -> tuple[str, ...]:
    """``"a.b.c"`` -> ``("a", "a.b", "a.b.c")`` -- outermost package first."""
    parts = module_name.split(".")
    return tuple(".".join(parts[: index + 1]) for index in range(len(parts)))


def _module_file(module_name: str) -> Path | None:
    """Locate a module's file on disk without executing the module.

    ``find_spec`` consults the import machinery but does not run the target. It
    does run the target's *parent* when the name is dotted, which is why the
    caller announces the plugin as running before it gets here.
    Returns ``None`` when there is no file to point at: built-in modules report
    ``origin == "built-in"``, frozen modules ``"frozen"``, and namespace packages
    report ``None``. A loader that trusts exactly one directory has no business
    accepting any of them, so all three become a refusal at the call site.
    """
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, ValueError):
        return None
    origin = getattr(spec, "origin", None)
    if not origin:
        return None
    path = Path(origin)
    return path.resolve() if path.is_file() else None


def _why_unresolvable(module_name: str, root: Path) -> str:
    """Which of several reasons a module has no file, decided from disk.

    The refusal this accompanies is correct however it was arrived at, but it
    names the check rather than the mistake, and the mistake is nearly always one
    of four things. Listing all four and making the reader work out which is
    theirs is not much better than saying nothing, so look instead: the folder is
    on disk or it is not, it has an ``__init__.py`` or it does not, the root is on
    ``sys.path`` or it is not. Those three facts separate every case below.

    Path arithmetic and ``sys.path`` only. Nothing here imports or resolves, and
    it runs after the refusal is already decided -- a wrong guess about *why*
    would be a bad diagnosis, never a permission.
    """
    parts = module_name.split(".")
    folder = root.joinpath(*parts)
    module_file = root.joinpath(*parts[:-1], f"{parts[-1]}.py")
    on_sys_path = any(entry and Path(entry).resolve() == root for entry in sys.path)

    if folder.is_dir() and not (folder / "__init__.py").is_file():
        return (
            f"that folder is on disk but has no __init__.py, so Python treats it as "
            f"a namespace package and it resolves to no single file. Create an empty "
            f"'{folder / '__init__.py'}'."
        )
    if not ((folder / "__init__.py").is_file() or module_file.is_file()):
        return (
            f"no '{parts[-1]}{os.sep}__init__.py' and no '{parts[-1]}.py' inside that "
            f"root. Check the entrypoint in manifest.json against the names on disk."
        )
    if not on_sys_path:
        return (
            f"the file is there, but '{root}' is not on sys.path, so the import "
            f"system cannot see it. preflight never modifies sys.path for you -- add "
            f"sys.path.insert(0, {str(root)!r}) before loading."
        )
    return (
        f"the file is there and that root is on sys.path, so something earlier on "
        f"sys.path is answering to '{module_name}' first. Rename the plugin folder "
        f"to a name no installed package already uses."
    )


def _import_entrypoint(
    entrypoint: str,
    trusted_root: Path | str,
    *,
    about_to_import: Callable[[], None] | None = None,
) -> object:
    """Import an entrypoint only if its module lives inside ``trusted_root``.

    The manifest *file* is confined to the trusted root by the caller. The
    entrypoint *string* is not: :class:`~preflight.manifest.PluginPackageManifest`
    validates its shape, not its location, so without this a manifest sitting
    inside the trusted root could name any importable module on ``sys.path``.

    The module is therefore resolved to a file before it is imported, and each
    ancestor package is cleared before its child is looked up -- ``find_spec``
    on a dotted name imports the parent as a side effect, so the parent has to
    pass the boundary first. On no path through this function does code outside
    the trusted root execute.

    preflight never modifies ``sys.path``. Putting the plugin directory on the
    import path is the host's job, and doing it here would mean mutating global
    import state as a side effect of a security check.

    ``about_to_import`` is called immediately before the plugin's code can run
    and never influences it. It exists so a caller can report *"this plugin's
    code ran"* honestly rather than inferring it from which error message came
    back. Note that for a dotted entrypoint that moment arrives during
    resolution, not at the import below -- see the loop.
    """
    module_name, attribute = entrypoint.split(":", 1)
    root = Path(trusted_root).resolve()
    announced = False

    def announce() -> None:
        """Report that the plugin's code is about to run, once, before it does."""
        nonlocal announced
        if about_to_import is not None and not announced:
            about_to_import()
        announced = True

    for ancestor in _import_chain(module_name):
        # `find_spec` on a dotted name imports the parent package to reach its
        # __path__. So for any entrypoint but a top-level one, the plugin's own
        # code runs *here*, during resolution, and not at the import below. The
        # parent has already cleared the boundary by this point -- the chain is
        # outermost first -- so this is a reporting line and not a security one.
        # Without it, a package whose __init__ runs and then raises is reported
        # as `never imported`, which is the one thing this library cannot get
        # wrong: the whole report is a claim about what did and did not execute.
        if "." in ancestor:
            announce()
        located = _module_file(ancestor)
        if located is None:
            raise PluginRejected(
                f"entrypoint module '{ancestor}' has no file on disk, so it cannot "
                f"be shown to live inside the trusted plugin root '{root}'\n"
                f"{_why_unresolvable(ancestor, root)}"
            )
        if not located.is_relative_to(root):
            raise PluginRejected(
                f"entrypoint module '{ancestor}' resolves to '{located}', which is "
                f"outside the trusted plugin root '{root}'"
            )

    # Past this line the plugin's own code is about to run. Everything above was
    # decided with the module still inert on disk -- unless the entrypoint was
    # dotted, in which case `announce` already fired during resolution and this
    # call is the no-op that says so.
    announce()
    module = importlib.import_module(module_name)

    # Defence in depth: re-check what actually loaded. Resolution and import are
    # two steps, and sys.modules is global mutable state in between them.
    loaded_from = getattr(module, "__file__", None)
    if loaded_from is None or not Path(loaded_from).resolve().is_relative_to(root):
        raise PluginRejected(
            f"entrypoint module '{module_name}' was imported from '{loaded_from}', "
            f"which is outside the trusted plugin root '{root}'"
        )

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
        refuse_tool_risks: Iterable[ToolRisk | str] = (),
        max_manifest_bytes: int | None = None,
    ) -> None:
        self.edition = Edition(edition)
        self.platform = Platform(platform) if platform is not None else host_platform()
        self.allowed_package_ids = frozenset(allowed_package_ids)
        self.refuse_tool_risks = frozenset(ToolRisk(risk) for risk in refuse_tool_risks)
        self.max_manifest_bytes = (
            self.MAX_MANIFEST_BYTES if max_manifest_bytes is None else max_manifest_bytes
        )
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
                manifest_error_message(
                    f"invalid plugin package manifest from {origin}", exc
                )
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
        except PluginRejected:
            raise  # already a refusal; do not relabel it as a malfunction
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
            # from_file=False: this came back from the plugin's own code, not off
            # disk, so "it belongs to another system" is not a verdict available
            # here -- there is no file for it to belong to.
            raise PluginRejected(
                manifest_error_message(
                    f"runtime manifest for '{package.package_id}' is invalid",
                    exc,
                    from_file=False,
                )
            ) from exc
        if runtime_manifest != package.plugin:
            # Equality is the whole check, but "not equal" is not a whole
            # message: the reader is left diffing a manifest against a source
            # file by eye. Both objects are here, so say which fields disagree.
            refusal = (
                f"runtime manifest for '{package.package_id}' does not match "
                "its validated package manifest"
            )
            differences = manifest_differences(package.plugin, runtime_manifest)
            raise PluginRejected("\n".join((refusal, *differences)))

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
        """Load one manifest confined to ``trusted_root`` and then its entry point.

        ``importer`` is a seam for tests and for hosts with their own import
        rules. Note what that means: entrypoint confinement is a property of the
        default importer, so a host that supplies its own owns that decision.
        """
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
        if size > self.max_manifest_bytes:
            raise PluginRejected(
                f"plugin manifest '{path}' exceeds {self.max_manifest_bytes} bytes"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            package = PluginPackageManifest.model_validate(payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
            raise PluginRejected(
                manifest_error_message(f"invalid plugin manifest '{path}'", exc)
            ) from exc

        return self.register(
            package,
            lambda: importer(package.entrypoint, root),
            origin=str(path),
        )

    def _validate_preload_policy(self, package: PluginPackageManifest) -> None:
        # The allowlist stays here rather than in `preload_refusals`. It is a
        # host's decision, and the other caller of that function is a terminal
        # command with no host to have made one.
        if package.package_id not in self.allowed_package_ids:
            raise PluginRejected(
                f"package '{package.package_id}' is not in the explicit build allowlist"
            )

        # First refusal wins, as it always has: a person fixes one thing at a
        # time and the registry has no report to put a list in. `preflight check`
        # calls the same function and shows all of them, because there the reader
        # is deciding rather than debugging.
        reasons = preload_refusals(
            package,
            platform=self.platform,
            edition=self.edition,
            refuse_tool_risks=self.refuse_tool_risks,
        )
        if reasons:
            raise PluginRejected(reasons[0])


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
