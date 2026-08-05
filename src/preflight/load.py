"""The front door: load a folder of plugins, and read what preflight decided.

    from preflight import load_plugins

    result = load_plugins("plugins", allow=["example.greeter"])
    print(result)
    greeter = result.plugins["greeter"]

This is a convenience layer over :class:`~preflight.registry.PluginRegistry` and
adds no permission to it. ``allow`` is required and has no wildcard: a package
sitting in the folder but absent from ``allow`` is never imported, which is the
same guarantee the registry gives and is tested as such.

What this layer does add is a report. A refusal that only exists as an exception
string tells a human very little; the report below says which plugins were
stopped *while still inert on disk* and which had already run, because that
distinction is the honest measure of what preflight did for you.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from preflight.manifest import Platform, Plugin, ToolRisk
from preflight.registry import (
    Edition,
    PluginRegistry,
    PluginRejected,
    _import_entrypoint,
)

#: The filename preflight looks for in each plugin package directory.
MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class Policy:
    """Optional settings. Every default is the strictest available value.

    Passing no policy at all is the safest thing you can do; each field below
    only ever appears in a call because a host deliberately widened or narrowed
    something.

    ``Policy`` is never loaded from disk, and that is deliberate. The command
    line can remember your preferences for you -- see ``preflight settings`` --
    but a running host states its policy here, in its own source, where it is
    reviewable, diffable, and cannot be moved by anything that ships in a plugin
    folder. ``preflight settings --as-python`` prints the call to paste, so the
    crossing from one to the other is an explicit human act rather than a file
    preflight reads behind your back.
    """

    #: Which visibility/release-ring tiers this build accepts. Rarely needed.
    edition: Edition = Edition.PUBLIC
    #: Defaults to the running OS. Set it to test another platform's decisions.
    platform: Platform | str | None = None
    #: Declared tool risks this host refuses outright, before importing.
    refuse_tool_risks: frozenset[ToolRisk] = field(default_factory=frozenset)
    #: Manifests larger than this are refused before they are read.
    max_manifest_bytes: int = PluginRegistry.MAX_MANIFEST_BYTES


@dataclass(frozen=True)
class Outcome:
    """What preflight decided about one plugin package, and when."""

    folder: str
    loaded: bool
    #: ``True`` if the plugin's own code executed before the decision was made.
    #: Read this before trusting a refusal to have cost the plugin nothing.
    code_ran: bool
    plugin_id: str | None = None
    name: str | None = None
    version: str | None = None
    tool_count: int = 0
    reason: str | None = None

    @property
    def stage(self) -> str:
        """A plain-English answer to 'how far did this plugin get?'"""
        if self.loaded:
            return "loaded"
        return "imported, then rejected" if self.code_ran else "never imported"


@dataclass(frozen=True)
class LoadReport:
    """The result of one :func:`load_plugins` call, and a readable summary."""

    directory: Path
    outcomes: tuple[Outcome, ...]
    registry: PluginRegistry

    @property
    def plugins(self) -> dict[str, Plugin]:
        """Every plugin that loaded, by plugin id."""
        return {
            manifest.plugin_id: instance
            for manifest in self.registry.available()
            if (instance := self.registry.get(manifest.plugin_id)) is not None
        }

    @property
    def loaded(self) -> tuple[Outcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.loaded)

    @property
    def refused(self) -> tuple[Outcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.loaded)

    def get(self, plugin_id: str) -> Plugin | None:
        return self.registry.get(plugin_id)

    def __str__(self) -> str:
        return self.text()

    def text(self) -> str:
        """The report, formatted for a person reading a terminal."""
        found = len(self.outcomes)
        # ASCII only. This gets printed to consoles preflight does not control,
        # and a report that arrives as mojibake is a report nobody reads.
        lines = [
            f"preflight | {self.directory.name}{os.sep} | "
            f"{found} package{'' if found == 1 else 's'} found",
            "",
        ]
        if not self.outcomes:
            lines.append(f"  no {MANIFEST_NAME} found in any subfolder")
            lines.append("")
            lines.append("  preflight has nothing to check. That is not a verdict.")
            return "\n".join(lines)

        width = max(len(outcome.folder) for outcome in self.outcomes)
        for outcome in self.outcomes:
            label = "LOADED " if outcome.loaded else "REFUSED"
            detail = (
                f"{outcome.name} {outcome.version} - "
                f"{outcome.tool_count} tool{'' if outcome.tool_count == 1 else 's'}"
                if outcome.loaded
                else outcome.stage
            )
            lines.append(f"  {label}  {outcome.folder:<{width}}  {detail}")
            # A reason may run to several lines -- a manifest with three bad
            # fields is a list, not a sentence. Every line of it sits under the
            # same column, or the second one reads as a row of its own.
            indent = " " * (2 + len(label) + 2 + width + 2)
            for line in (outcome.reason or "").splitlines():
                lines.append(f"{indent}{line}".rstrip())

        refused = self.refused
        summary = f"  {len(self.loaded)} loaded, {len(refused)} refused"
        if refused:
            inert = sum(1 for outcome in refused if not outcome.code_ran)
            summary += (
                f" -- {inert} of the {len(refused)} "
                "stopped before any of their code ran"
            )
        lines.extend(["", summary])
        return "\n".join(lines)


def load_plugins(
    directory: Path | str,
    *,
    allow: Iterable[str],
    policy: Policy | None = None,
) -> LoadReport:
    """Load every allowed plugin package in ``directory`` and report the outcome.

    ``directory`` is the trusted root. Each plugin package is a subfolder of it
    holding a ``manifest.json`` and its Python, and nothing outside it may be
    imported as an entrypoint.

    ``allow`` lists the ``package_id`` of every package this host accepts. It is
    required and there is no wildcard. Discovery is only a convenience for the
    loop a host would otherwise write by hand -- it is the allowlist, not the
    absence of a scan, that keeps an unexpected folder from loading.
    """
    allow = tuple(allow)  # read twice below; a generator would empty on the first
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"plugin directory '{root}' does not exist")

    # preflight never modifies sys.path; putting the plugin folder on the import
    # path is the host's call. But failing that check produces a pile of "no file
    # on disk" refusals that read like a preflight bug, so say what is wrong.
    if not any(Path(entry).resolve() == root for entry in sys.path if entry):
        raise RuntimeError(
            f"'{root}' is not on sys.path, so none of its plugins can be imported.\n"
            f"preflight does not modify sys.path for you. Add this line first:\n"
            f"    sys.path.insert(0, {str(root)!r})"
        )

    settings = policy or Policy()
    registry = PluginRegistry(
        edition=settings.edition,
        allowed_package_ids=allow,
        platform=settings.platform,
        refuse_tool_risks=settings.refuse_tool_risks,
        max_manifest_bytes=settings.max_manifest_bytes,
    )

    outcomes = [
        _attempt(registry, manifest_path, root)
        for manifest_path in _in_allow_order(root, allow)
    ]
    return LoadReport(directory=root, outcomes=tuple(outcomes), registry=registry)


def _in_allow_order(root: Path, allow: Iterable[str]) -> list[Path]:
    """Order the discovered manifests by the host's allowlist, then by name.

    Load order is not cosmetic: the first plugin to claim a tool name keeps it,
    so whoever goes first wins a collision. Left to ``glob`` that would be decided
    alphabetically -- by the filesystem, which no one chose. Ordering by ``allow``
    puts precedence back in the host's hands, where it is written down.

    The peek at ``package_id`` below reads the file to *sort* it and nothing else.
    Every decision about whether a package may load is still made downstream by
    the registry against the fully validated manifest.
    """
    discovered = sorted(root.glob(f"*/{MANIFEST_NAME}"))
    by_package_id: dict[str, Path] = {}
    for path in discovered:
        try:
            package_id = json.loads(path.read_text(encoding="utf-8"))["package_id"]
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, KeyError):
            continue  # unreadable or malformed; the registry will say so properly
        by_package_id.setdefault(str(package_id), path)

    ordered: list[Path] = []
    for package_id in allow:
        path = by_package_id.get(package_id)
        if path is not None and path not in ordered:
            ordered.append(path)
    ordered.extend(path for path in discovered if path not in ordered)
    return ordered


def _attempt(registry: PluginRegistry, manifest_path: Path, root: Path) -> Outcome:
    """Load one package, recording whether its code ran before the decision."""
    code_ran = False

    def importer(entrypoint: str, trusted_root: Path) -> object:
        def ran() -> None:
            nonlocal code_ran
            code_ran = True

        return _import_entrypoint(entrypoint, trusted_root, about_to_import=ran)

    folder = manifest_path.parent.name
    try:
        registered = registry.load_manifest_file(
            manifest_path, trusted_root=root, importer=importer
        )
    except PluginRejected as refusal:
        return Outcome(folder=folder, loaded=False, code_ran=code_ran, reason=str(refusal))

    plugin = registered.package.plugin
    return Outcome(
        folder=folder,
        loaded=True,
        code_ran=True,
        plugin_id=plugin.plugin_id,
        name=plugin.name,
        version=plugin.module_version,
        tool_count=len(plugin.tools),
    )
