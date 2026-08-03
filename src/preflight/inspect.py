"""Read a plugin package's paperwork without executing any of it.

This module answers one question: *what does this package claim the right to do,
and does its manifest hold up?* It is what ``preflight check`` runs, and it is
the only part of preflight that is safe to point at code you have not read.

It imports nothing. Not the plugin, not ``importlib``, not ``find_spec`` -- note
that :func:`~preflight.registry._import_entrypoint` cannot avoid ``find_spec``,
and ``find_spec("a.b")`` imports ``a`` as a side effect, which is why the loader
checks ancestors one at a time. Here there is no such problem to solve, because
an entrypoint is resolved by path arithmetic against the folder on disk. Nothing
in this module can cause a line of the inspected package to run, and
``test_inspect.py`` proves it with a tripwire.

What it cannot do, stated here so nothing downstream has to imply otherwise: it
does not read the package's code, detect malicious behaviour, or verify that the
implementation matches the manifest. It reads a declaration. A package that
declares itself accurately and then does something else will pass every check in
this file.
"""

from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from preflight.manifest import PluginPackageManifest, Tool, ToolRisk

MANIFEST_NAME = "manifest.json"

#: Plain-English gloss for each declared risk. These describe what the *manifest
#: claims*, never what the code does -- preflight has not read the code.
_RISK_MEANING: dict[ToolRisk, str] = {
    ToolRisk.READ: "reads data",
    ToolRisk.WRITE: "changes data",
    ToolRisk.DESTRUCTIVE: "deletes things",
    ToolRisk.FINANCIAL: "can spend money",
    ToolRisk.CREDENTIAL: "handles secrets",
    ToolRisk.SECURITY: "changes security settings",
    ToolRisk.PUBLIC_POSTING: "publishes in public",
    ToolRisk.SENSITIVE_DISCLOSURE: "can reveal sensitive data",
}


@dataclass(frozen=True)
class Inspection:
    """Everything that can be learned about a package without running it."""

    folder: Path
    manifest_path: Path | None = None
    package: PluginPackageManifest | None = None
    #: Where the entrypoint module would have to live, if it is inside the folder.
    entrypoint_file: Path | None = None
    #: Why the manifest or the entrypoint did not hold up, if it did not.
    problem: str | None = None
    #: The file is a ``manifest.json``, but it belongs to some other system --
    #: it declares not one of the fields preflight requires. This is a different
    #: report from an invalid manifest, because nothing about it is wrong.
    foreign_manifest: bool = False

    @property
    def has_manifest(self) -> bool:
        return self.manifest_path is not None

    @property
    def consistent(self) -> bool:
        """The manifest parsed and its entrypoint points inside the folder."""
        return self.package is not None and self.entrypoint_file is not None

    def refused_tools(self, risks: Iterable[ToolRisk | str]) -> tuple[Tool, ...]:
        """The declared tools carrying a risk in ``risks``.

        This is the same decision :class:`~preflight.registry.PluginRegistry`
        makes from ``refuse_tool_risks``, asked of a package that is not being
        loaded. It reads the parsed manifest and nothing else -- a tool the
        package never declared is invisible to it, exactly as it is to the gate.
        """
        if self.package is None:
            return ()
        refused = frozenset(ToolRisk(risk) for risk in risks)
        return tuple(tool for tool in self.package.plugin.tools if tool.risk in refused)


#: How many individual field errors are worth printing before the list stops
#: being read. Past this a person is scrolling, not deciding.
_MAX_REPORTED_ERRORS = 6

#: Prose in a report is wrapped to this, and indented by two when printed. The
#: field tables below are not wrapped -- a column that moves is worse to read
#: than one that runs long.
_LINE = 68


def _required_fields() -> tuple[str, ...]:
    """The manifest fields with no default, in declaration order.

    Derived from the model rather than listed here, so it stays true if the
    schema gains or loses one.
    """
    return tuple(
        name
        for name, field in PluginPackageManifest.model_fields.items()
        if field.is_required()
    )


def _explain(exc: Exception) -> tuple[str, bool]:
    """Why the manifest did not parse, in words, and whether it is even ours.

    ``str(ValidationError)`` is a per-error dump with a documentation URL and an
    echo of the input under every entry -- upwards of fifty lines for a file
    whose only crime is belonging to a different tool. Plenty of systems keep a
    ``manifest.json``, so someone pointing ``check`` at a browser extension or a
    web app is not making a mistake, they are testing what this thing is. That
    is the moment they decide preflight is broken, and a wall of pydantic is how
    they decide it. Answer with the short true thing and the next command.

    Returns the description, and whether the file is another system's manifest.
    """
    if not isinstance(exc, ValidationError):
        return str(exc), False

    errors = exc.errors()
    required = _required_fields()
    absent = {
        str(error["loc"][0])
        for error in errors
        if error["type"] == "missing" and len(error["loc"]) == 1
    }
    unknown = sum(1 for error in errors if error["type"] == "extra_forbidden")

    # Not one required field is present. A preflight manifest with a mistake in
    # it still looks like a preflight manifest; this does not look like one at
    # all, and calling it invalid would be a false claim about someone else's
    # perfectly good file.
    if absent >= set(required):
        return (
            textwrap.fill(
                f"This is a manifest.json, but not one of preflight's. It has "
                f"none of the fields preflight requires ({', '.join(required)}), "
                f"and {unknown} that preflight does not recognise.",
                width=_LINE,
            ),
            True,
        )

    shown = errors[:_MAX_REPORTED_ERRORS]
    count = len(errors)
    lines = [f"{count} problem{'' if count == 1 else 's'} with this manifest:"]
    width = max(len(_where(error)) for error in shown)
    lines += [f"  {_where(error):<{width}}  {error['msg']}" for error in shown]
    if count > len(shown):
        lines.append(f"  ... and {count - len(shown)} more")
    return "\n".join(lines), False


def _where(error: dict) -> str:
    """The dotted path to the field an error is about."""
    return ".".join(str(part) for part in error["loc"]) or "(the file itself)"


def _resolve_on_disk(module_name: str, import_root: Path) -> tuple[Path | None, str]:
    """Locate a dotted module under ``import_root`` using the filesystem alone.

    This mirrors what the import system would find, minus the part that runs the
    code. Every ancestor must be a real package, because a directory without an
    ``__init__.py`` is a namespace package, and the loader refuses those: they
    resolve to no single file, so they cannot be shown to be inside the root.
    """
    parts = module_name.split(".")
    for depth in range(len(parts) - 1):
        ancestor = import_root.joinpath(*parts[: depth + 1])
        if not (ancestor / "__init__.py").is_file():
            dotted = ".".join(parts[: depth + 1])
            return None, (
                f"'{dotted}' is not a package inside this folder "
                f"(no {dotted}{os.sep}__init__.py)"
            )

    base = import_root.joinpath(*parts)
    if (base / "__init__.py").is_file():
        return base / "__init__.py", ""
    leaf = base.parent / f"{base.name}.py"
    if leaf.is_file():
        return leaf, ""
    return None, (
        f"no file for '{module_name}' inside this folder; this entrypoint "
        f"points outside the only directory preflight would trust"
    )


def inspect_package(folder: Path | str, *, import_root: Path | str | None = None) -> Inspection:
    """Inspect one plugin package directory. Executes nothing.

    ``import_root`` is the directory the entrypoint's dotted name is resolved
    against, and defaults to the package folder's parent -- the layout the loader
    expects, where the trusted root holds one subfolder per package.
    """
    package_folder = Path(folder).resolve()
    root = Path(import_root).resolve() if import_root else package_folder.parent
    manifest_path = package_folder / MANIFEST_NAME

    if not manifest_path.is_file():
        return Inspection(folder=package_folder)

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        package = PluginPackageManifest.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        problem, foreign = _explain(exc)
        return Inspection(
            folder=package_folder,
            manifest_path=manifest_path,
            problem=problem,
            foreign_manifest=foreign,
        )

    module_name = package.entrypoint.split(":", 1)[0]
    located, problem = _resolve_on_disk(module_name, root)
    return Inspection(
        folder=package_folder,
        manifest_path=manifest_path,
        package=package,
        entrypoint_file=located,
        problem=problem or None,
    )


def inspect_directory(directory: Path | str) -> tuple[Inspection, ...]:
    """Inspect a folder. Handles both a single package and a folder of them.

    Never returns empty. A folder with no manifest anywhere is reported as one
    package that has none, because "I looked and there was nothing to check" is
    a result a caller has to show a person, not an empty list to skip past.
    """
    target = Path(directory).resolve()
    if (target / MANIFEST_NAME).is_file():
        return (inspect_package(target),)
    found = tuple(
        inspect_package(manifest.parent, import_root=target)
        for manifest in sorted(target.glob(f"*/{MANIFEST_NAME}"))
    )
    return found or (Inspection(folder=target),)


def _as_policy_call(risks: Iterable[ToolRisk]) -> str:
    """Render a refused-risk set as the ``Policy`` a host would actually write.

    The command line exists to inform a decision that gets enforced somewhere
    else. Printing the enforcing call by name is the shortest way to say so.
    """
    members = ", ".join(f"ToolRisk.{risk.name}" for risk in sorted(risks, key=lambda r: r.name))
    return f"Policy(refuse_tool_risks={{{members}}})"


def format_inspection(
    inspection: Inspection,
    *,
    refuse_tool_risks: Iterable[ToolRisk | str] = (),
) -> str:
    """The inspection, written for a person deciding whether to install this.

    ``refuse_tool_risks`` are the risks the reader has said they will not accept.
    Tools declaring one are marked and named, and the verdict at the bottom says
    the package would be refused -- by that rule, not by preflight's.
    """
    refused = frozenset(ToolRisk(risk) for risk in refuse_tool_risks)
    refused_tools = inspection.refused_tools(refused)
    refused_names = {tool.name for tool in refused_tools}
    name = inspection.folder.name
    # ASCII only -- see the note in preflight.load.LoadReport.text.
    lines = [f"preflight check | {name}{os.sep} | nothing was executed", ""]

    if not inspection.has_manifest:
        lines += [
            f"  no {MANIFEST_NAME} found",
            "",
            "  This package makes no declarations preflight can check, so preflight",
            "  can tell you nothing about it. That is not a verdict on the package;",
            "  it is the absence of one.",
            "",
            "  To adopt it anyway, write down what you will permit it to do:",
            f"      preflight create {name}",
        ]
        return "\n".join(lines)

    if inspection.package is None:
        detail = [f"  {line}" for line in (inspection.problem or "").splitlines()]
        if inspection.foreign_manifest:
            lines += [
                "  manifest      not preflight's",
                "",
                *detail,
                "",
                "  Plenty of systems keep a file by that name, and preflight cannot",
                "  read theirs -- it would have to guess what any of it permits. A",
                "  preflight manifest is written by whoever sets the terms for",
                "  loading: the package's author, when your host requires one, or",
                "  you, when you adopt something that never heard of preflight.",
                "",
                "  Writing yours means taking that filename:",
                f"      preflight create {name} --force",
                "",
                "  That replaces the file above. Move theirs aside first if the",
                "  tool it belongs to still needs it.",
            ]
        else:
            lines += [
                "  manifest      INVALID",
                "",
                *detail,
                "",
                "  preflight refuses a manifest it cannot fully understand rather than",
                "  ignoring the parts it does not recognise.",
            ]
        return "\n".join(lines)

    package = inspection.package
    plugin = package.plugin
    lines += [
        f"  manifest      valid",
        f"  package id    {package.package_id}",
        f"  plugin        {plugin.name} {plugin.module_version}  (id: {plugin.plugin_id})",
        f"  tier          {package.visibility.value}, {package.release_ring.value} ring",
        f"  entrypoint    {package.entrypoint}",
    ]
    if inspection.entrypoint_file is not None:
        relative = inspection.entrypoint_file.relative_to(inspection.folder.parent)
        lines.append(f"                -> {relative}  (inside this folder)")
    else:
        lines.append(f"                XX {inspection.problem}")

    if plugin.supported_platforms:
        platforms = ", ".join(p.value for p in plugin.supported_platforms)
        lines.append(f"  platforms     {platforms}")
    if plugin.permissions:
        lines.append(f"  permissions   {', '.join(plugin.permissions)}")
    if plugin.data_classes:
        lines.append(f"  data classes  {', '.join(plugin.data_classes)}")

    lines.append("")
    if plugin.tools:
        count = len(plugin.tools)
        lines.append(f"  declares {count} tool{'' if count == 1 else 's'}")
        width = max(len(tool.name) for tool in plugin.tools)
        risk_width = max(len(tool.risk.value) for tool in plugin.tools)
        for tool in plugin.tools:
            meaning = _RISK_MEANING.get(tool.risk, "")
            # Anything beyond a read is worth a reader's eye before installing.
            # A risk the reader has already excluded gets a stronger mark: this
            # one is not a prompt to think, it is a decision already made.
            if tool.name in refused_names:
                flag = "X "
            else:
                flag = "  " if tool.risk is ToolRisk.READ else "! "
            lines.append(
                f"    {flag}{tool.name:<{width}}  {tool.risk.value:<{risk_width}}  {meaning}"
            )
    else:
        lines.append("  declares no tools")

    if refused_tools:
        count = len(refused_tools)
        listed = ", ".join(f"{tool.name} ({tool.risk.value})" for tool in refused_tools)
        verb = "declares" if count == 1 else "declare"
        lines += [
            "",
            f"  {count} tool{'' if count == 1 else 's'} {verb} a risk you refused: {listed}",
            f"  A host running {_as_policy_call(refused)} would",
            "  refuse this package before importing it.",
        ]

    lines.append("")
    if not inspection.consistent:
        lines.append("  This package would be refused. Its code would never be imported.")
    elif refused_tools:
        lines += [
            "  Paperwork is consistent, and this package would still be refused --",
            "  by your rule, not by preflight's. Its code would never be imported.",
        ]
    else:
        lines += [
            "  Paperwork is consistent. preflight did not run this code and cannot",
            "  tell you whether it does what it says.",
        ]
    return "\n".join(lines)
