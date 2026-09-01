"""Read a plugin package's paperwork without executing any of it.

This module answers one question: *what does this package claim the right to do,
and does its manifest hold up?* It is what ``preflight check`` runs, and it is
the only part of preflight that is safe to point at code you have not read.

It imports nothing. Not the plugin, not ``importlib``, not ``find_spec`` -- note
that :func:`~preflight.registry._import_entrypoint` cannot avoid ``find_spec``,
and ``find_spec("a.b")`` imports ``a`` as a side effect, which is why the loader
checks ancestors one at a time. Here there is no such problem to solve, because
an entrypoint is resolved by path arithmetic against the folder on disk. The one
question path arithmetic cannot answer -- whether the interpreter already owns
the name the folder is using -- is settled by reading two frozensets the
interpreter carries, ``sys.builtin_module_names`` and ``sys.stdlib_module_names``,
which is a lookup and not an import. Nothing in this module can cause a line of
the inspected package to run, and ``test_inspect.py`` proves it with a tripwire.

One thing here does open the package's own source: the entrypoint's
``:attribute`` half is looked for with :func:`ast.parse`, which builds a tree
and evaluates none of it. Reading a file is not running it, and this is the
only way to answer *"would the gate's ``getattr`` succeed?"* without the import
that would make the question moot.

What it cannot do, stated here so nothing downstream has to imply otherwise: it
does not understand the package's code, detect malicious behaviour, or verify
that the implementation matches the manifest. It reads a declaration, and one
name out of a syntax tree. A package that declares itself accurately and then
does something else will pass every check in this file.
"""

from __future__ import annotations

import ast
import json
import os
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from preflight.manifest import (
    Platform,
    PluginPackageManifest,
    Tool,
    ToolRisk,
    explain_manifest_error,
)
from preflight.registry import (
    Edition,
    PluginRegistry,
    host_platform,
    interpreter_provides,
    no_file_refusal,
    preload_refusals,
)

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
    #: Why no host can reach this entrypoint by the name it uses, even though the
    #: file is on disk inside the folder. Set only when the entrypoint resolved --
    #: a name that is not on disk already has a ``problem``.
    unreachable_name: str | None = None
    #: Why the gate's ``getattr`` on the entrypoint would fail, found in the
    #: package's syntax tree. Set only when the entrypoint names an attribute
    #: and the file it would live in was read and parsed.
    missing_attribute: str | None = None
    #: Why importing the entrypoint source itself would fail. Kept in the late
    #: list because the runtime gate learns this only when it attempts import.
    source_problem: str | None = None
    #: Collisions that only become visible while inspecting a directory.
    directory_refusals: tuple[str, ...] = ()

    @property
    def adapts_the_module(self) -> bool:
        """The entrypoint is bare, so preflight supplies the ``Plugin`` wrapper.

        The package never states what it is, so there is no second statement for
        the gate to check this manifest against. Worth reporting: it is the one
        check in the table that a valid, fully consistent package can be missing.
        """
        return self.package is not None and not self.package.self_reports_manifest

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

        Named separately from :meth:`refusals` because the report marks these
        tools individually, in the list where they are declared. The sentence
        version of the same fact comes back from ``refusals`` too.
        """
        if self.package is None:
            return ()
        refused = frozenset(ToolRisk(risk) for risk in risks)
        return tuple(tool for tool in self.package.plugin.tools if tool.risk in refused)

    def refusals(
        self,
        *,
        platform: Platform | None = None,
        edition: Edition = Edition.PUBLIC,
        refuse_tool_risks: Iterable[ToolRisk | str] = (),
    ) -> tuple[str, ...]:
        """Every reason a host with these rules would refuse this package.

        The same function the gate calls -- see
        :func:`~preflight.registry.preload_refusals`. Calling it rather than
        re-deriving the answer here is what stops ``check`` and ``load_plugins``
        from drifting into two opinions, which they had: this command judged the
        declared risks and nothing else, so a package the gate would turn away
        for its platform or its release ring passed and exited zero.

        Empty when the manifest did not parse. There is nothing to decide about
        a package whose declaration could not be read, and the report says so
        further up.
        """
        if self.package is None:
            return ()
        reasons = preload_refusals(
            self.package,
            platform=platform if platform is not None else host_platform(),
            edition=edition,
            refuse_tool_risks=refuse_tool_risks,
        )
        # Last, because that is where the gate reaches it. `register` applies
        # every preload rule and raises on the first, and only then resolves the
        # entrypoint -- so a package that is both refused for its platform and
        # named after a builtin is refused for its platform, and this reason is
        # one the host would never get as far as printing.
        if self.unreachable_name is not None:
            reasons = (*reasons, self.unreachable_name)
        return (*reasons, *self.directory_refusals)

    def late_refusals(self) -> tuple[str, ...]:
        """Every reason a host would refuse this package *after* importing it.

        Kept apart from :meth:`refusals` rather than appended to it, because the
        difference between the two lists is the thing this project is about. A
        package refused here has already run. Filing that under "reasons a host
        would refuse this before importing it" would be a lie told by the one
        command whose job is to tell the truth about what executes.

        Both lists mean exit ``1``. Only one of them means nothing happened.
        """
        return tuple(
            reason
            for reason in (self.source_problem, self.missing_attribute)
            if reason is not None
        )


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

    root = import_root.resolve()
    base = root.joinpath(*parts)
    candidate: Path | None = None
    if (base / "__init__.py").is_file():
        candidate = base / "__init__.py"
    leaf = base.parent / f"{base.name}.py"
    if candidate is None and leaf.is_file():
        candidate = leaf
    if candidate is not None:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            return None, (
                f"file for '{module_name}' resolves outside the trusted "
                f"plugin root '{root}'"
            )
        return resolved, ""
    return None, (
        f"no file for '{module_name}' inside this folder; this entrypoint "
        f"points outside the only directory preflight would trust"
    )


def _unreachable_name(module_name: str, import_root: Path) -> str | None:
    """Why no host could reach this entrypoint, though the file is right there.

    This is the one thing the gate decides that path arithmetic cannot see, and
    it is where the two commands disagreed. :func:`_resolve_on_disk` finds
    ``root/json/__init__.py`` and stops; the loader asks the import system, which
    hands back the standard library's copy and refuses the package for pointing
    outside the root. A package named after a builtin never resolves at all.
    Either way ``check`` printed "Paperwork is consistent" and exited ``0`` on a
    package that cannot load anywhere -- while the manual recommends running it
    in CI precisely so a startup refusal is caught at review time.

    Decided from ``sys.builtin_module_names`` and ``sys.stdlib_module_names``.
    Nothing is imported. ``find_spec`` would answer this exactly and, on a dotted
    name, by running the parent package -- which is the one thing this module may
    not do.
    """
    top = module_name.split(".", 1)[0]
    provided = interpreter_provides(top)
    if provided == "builtin":
        # Unconditional, so say it in the gate's own words by calling the gate's
        # own function. `on_sys_path=True` because the host this predicts has the
        # root on sys.path -- `load_plugins` refuses to run without it -- whereas
        # this process never will, and the honest diagnosis is the host's.
        return no_file_refusal(top, import_root, on_sys_path=True)
    if provided == "stdlib":
        # Not unconditional, and the gate's wording quotes a path `find_spec`
        # resolved -- which is exactly what this module may not ask for. Guessing
        # it from `sysconfig` would be a guess about a different interpreter than
        # the host's, and a wrong verbatim quote is worse than an honest
        # paraphrase. So this one is check's own sentence, and it names both
        # futures rather than claiming the one it cannot know.
        return (
            f"entrypoint module '{top}' is a standard library module name. A host "
            f"that has already imported '{top}' refuses this package for resolving "
            f"outside the trusted plugin root '{import_root}'; one that has not "
            f"imports this folder in the standard library's place, for the rest of "
            f"the process. Rename the plugin folder and the entrypoint together."
        )
    return None


#: Refusal strings are wrapped to this before the report indents them. Narrower
#: than the manifest explainer's 68 because these sit two columns further in.
_REFUSAL_LINE = 64

#: Statements that can bind a module-level name inside another statement. A
#: ``def`` guarded by ``if sys.platform == ...`` is still a module attribute; a
#: ``def`` inside a function body is not. Descending into exactly these, and
#: never into a function or class body, is the difference.
_NESTS_TOP_LEVEL_CODE = (
    ast.If,
    ast.Try,
    ast.With,
    ast.AsyncWith,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Match,
)


def _target_binds(target: ast.AST | None, name: str) -> bool:
    """Whether an assignment-style target binds the requested name."""
    if target is None:
        return False
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_binds(item, name) for item in target.elts)
    if isinstance(target, ast.Starred):
        return _target_binds(target.value, name)
    return False


def _pattern_binds(pattern: ast.pattern, name: str) -> bool:
    """Whether structural pattern matching captures the requested name."""
    return any(
        isinstance(node, ast.MatchAs)
        and node.name == name
        or isinstance(node, ast.MatchStar)
        and node.name == name
        or isinstance(node, ast.MatchMapping)
        and node.rest == name
        for node in ast.walk(pattern)
    )


def _binds_at_module_level(body: list[ast.stmt], name: str) -> bool:
    """Whether these top-level statements bind ``name``, without running them."""
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
            continue  # its body is local scope, not module scope
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound == name:
                    return True
            continue
        if isinstance(node, ast.Assign):
            if any(_target_binds(target, name) for target in node.targets):
                return True
            continue
        if isinstance(node, ast.AnnAssign):
            if _target_binds(node.target, name):
                return True
            continue
        if isinstance(node, ast.AugAssign):
            if _target_binds(node.target, name):
                return True
            continue
        if any(
            isinstance(child, ast.NamedExpr) and _target_binds(child.target, name)
            for child in ast.walk(node)
        ):
            return True
        if isinstance(node, _NESTS_TOP_LEVEL_CODE):
            if isinstance(node, (ast.For, ast.AsyncFor)) and _target_binds(
                node.target, name
            ):
                return True
            if isinstance(node, (ast.With, ast.AsyncWith)) and any(
                _target_binds(item.optional_vars, name) for item in node.items
            ):
                return True
            if isinstance(node, ast.Try) and any(
                handler.name == name for handler in node.handlers
            ):
                return True
            if isinstance(node, ast.Match) and any(
                _pattern_binds(case.pattern, name) for case in node.cases
            ):
                return True
            nested: list[ast.stmt] = []
            if isinstance(node, ast.Match):
                for case in node.cases:
                    nested.extend(case.body)
            else:
                nested.extend(node.body)
                nested.extend(getattr(node, "orelse", []))
                nested.extend(getattr(node, "finalbody", []))
                for handler in getattr(node, "handlers", []):
                    nested.extend(handler.body)
            if _binds_at_module_level(nested, name):
                return True
            continue
    return False


def _defers_attribute_lookup(body: list[ast.stmt]) -> bool:
    """Whether this module can produce names that are not written in it.

    ``__getattr__`` (PEP 562) and ``from x import *`` both mean the attribute
    could exist at runtime with nothing in the file to show for it. Neither is
    common in a plugin, and both are cheap to spot -- and the alternative is
    ``check`` reporting a missing entrypoint that is not missing, which would
    make its exit code untrustworthy in the direction that matters.
    """
    for node in body:
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__":
            return True
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return True
    return False


def module_defines(path: Path, name: str) -> bool:
    """Whether this file binds ``name`` at module level, without running it.

    ``True`` when the name is written in the file, and also when the file could
    produce names that are not written in it -- see
    :func:`_defers_attribute_lookup`. Both callers want the same answer from an
    unreadable or unparseable file, which is ``True``: ``check`` will not report
    a missing entrypoint it cannot see, and ``create`` will not write a stub over
    a file it does not understand.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return True
    return _binds_at_module_level(tree.body, name) or _defers_attribute_lookup(
        tree.body
    )


def _source_parse_problem(path: Path) -> str | None:
    """Explain source that the interpreter cannot import, without executing it."""
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        where = f" at line {exc.lineno}" if exc.lineno else ""
        return textwrap.fill(
            f"entrypoint source {path.name} has invalid Python syntax{where}: "
            f"{exc.msg}. A host refuses it when import is attempted.",
            width=_REFUSAL_LINE,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return textwrap.fill(
            f"entrypoint source {path.name} cannot be read as Python: {exc}. "
            f"A host refuses it when import is attempted.",
            width=_REFUSAL_LINE,
        )
    return None


def _missing_entrypoint_attribute(entrypoint: str, located: Path) -> str | None:
    """Why the gate's ``getattr`` would fail, read from the file rather than run.

    ``check`` used to verify the module half of the entrypoint and say nothing
    about the ``:attribute`` half -- so a package with no ``create_plugin``
    printed "Paperwork is consistent", exited ``0``, and was then refused at
    startup *after its code had run*. That is the first thing a newcomer gets
    wrong and the last one ``check`` was willing to mention.

    Parsing is not executing: :func:`ast.parse` builds a tree and evaluates
    nothing. The tree cannot see an attribute a module invents at runtime, and
    :func:`module_defines` answers ``True`` in every case where it cannot tell --
    this reports a missing entrypoint only when the file plainly has none.
    """
    module_name, separator, attribute = entrypoint.partition(":")
    if not separator:
        return None  # nothing was promised, so nothing can be missing
    if module_defines(located, attribute):
        return None

    # Wrapped here rather than by the caller. Every other refusal string arrives
    # pre-broken at the width the report indents to, and a caller that wrapped
    # some of them and not others would have to know which.
    return textwrap.fill(
        f"entrypoint attribute '{attribute}' is not defined in {located.name}. "
        f"A host imports '{module_name}', asks for '{attribute}', and refuses "
        f"the package when it is not there -- by which time the package's code "
        f"has run. Define it in that file, or shorten the entrypoint to "
        f"'{module_name}' to have preflight adapt the module using this manifest.",
        width=_REFUSAL_LINE,
    )


def inspect_package(
    folder: Path | str, *, import_root: Path | str | None = None
) -> Inspection:
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
        size = manifest_path.stat().st_size
        if size > PluginRegistry.MAX_MANIFEST_BYTES:
            return Inspection(
                folder=package_folder,
                manifest_path=manifest_path,
                problem=(
                    f"manifest exceeds {PluginRegistry.MAX_MANIFEST_BYTES} bytes "
                    "and was not read"
                ),
            )
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        package = PluginPackageManifest.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        problem, foreign = explain_manifest_error(exc)
        return Inspection(
            folder=package_folder,
            manifest_path=manifest_path,
            problem=problem,
            foreign_manifest=foreign,
        )

    module_name = package.entrypoint.split(":", 1)[0]
    located, problem = _resolve_on_disk(module_name, root)
    source_problem = _source_parse_problem(located) if located else None
    return Inspection(
        folder=package_folder,
        manifest_path=manifest_path,
        package=package,
        entrypoint_file=located,
        problem=problem or None,
        # Only when it resolved. A name with no file under this root already has
        # a `problem` naming that, and saying it twice in different words would
        # read as two faults.
        unreachable_name=_unreachable_name(module_name, root) if located else None,
        # Same condition: without a file there is nothing to parse, and the
        # missing file is the finding.
        missing_attribute=(
            _missing_entrypoint_attribute(package.entrypoint, located)
            if located and source_problem is None
            else None
        ),
        source_problem=source_problem,
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
    if not found:
        return (Inspection(folder=target),)

    owners: dict[tuple[str, str], str] = {}
    annotated: list[Inspection] = []
    for inspection in found:
        package = inspection.package
        if package is None:
            annotated.append(inspection)
            continue
        collisions: list[str] = []
        claims = [
            ("package id", package.package_id),
            ("plugin id", package.plugin.plugin_id),
            *(("tool name", tool.name) for tool in package.plugin.tools),
        ]
        for kind, value in claims:
            key = (kind, value)
            owner = owners.get(key)
            if owner is not None:
                collisions.append(
                    f"{kind} '{value}' is already declared by folder '{owner}'"
                )
            else:
                owners[key] = inspection.folder.name
        annotated.append(
            replace(inspection, directory_refusals=tuple(collisions))
            if collisions
            else inspection
        )
    return tuple(annotated)


def risk_set_literal(risks: Iterable[ToolRisk]) -> str:
    """Render risks as the Python set literal a host would paste into its source.

    Shared with ``preflight settings --as-python``, which prints a whole
    ``Policy`` rather than this one field. Both have to spell ``ToolRisk`` the
    same way, because both are output a person copies verbatim.
    """
    members = ", ".join(
        f"ToolRisk.{risk.name}" for risk in sorted(risks, key=lambda r: r.name)
    )
    return f"{{{members}}}"


def _as_policy_call(risks: Iterable[ToolRisk]) -> str:
    """Render a refused-risk set as the ``Policy`` a host would actually write.

    The command line exists to inform a decision that gets enforced somewhere
    else. Printing the enforcing call by name is the shortest way to say so.
    """
    return f"Policy(refuse_tool_risks={risk_set_literal(risks)})"


def format_inspection(
    inspection: Inspection,
    *,
    refuse_tool_risks: Iterable[ToolRisk | str] = (),
    platform: Platform | None = None,
    edition: Edition = Edition.PUBLIC,
) -> str:
    """The inspection, written for a person deciding whether to install this.

    ``refuse_tool_risks`` are the risks the reader has said they will not accept.
    Tools declaring one are marked and named, and the verdict at the bottom says
    the package would be refused -- by that rule, not by preflight's.

    ``platform`` and ``edition`` are the rest of what a host decides before it
    imports anything, and they default to what a host with no ``Policy`` would
    use: the running OS, and a public build. They are here so this command
    answers the question the gate would answer, rather than a smaller one.
    """
    refused = frozenset(ToolRisk(risk) for risk in refuse_tool_risks)
    refused_tools = inspection.refused_tools(refused)
    refused_names = {tool.name for tool in refused_tools}
    # Asked with no risks at all, so what comes back is platform and tier alone.
    # The risk refusals are already shown against the tools that caused them, a
    # few lines down, and a sentence repeating each one would say it twice.
    # Subtracting them by matching on their wording would work until someone
    # reworded them; not asking for them cannot rot.
    other_refusals = inspection.refusals(platform=platform, edition=edition)
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
            # The folder, not its name. This line is copied and run, and the
            # basename only works from the parent directory -- which is not
            # where the reader necessarily is, because it is not where the
            # command they just ran was pointed. `create` prints the path too.
            f"      preflight create {inspection.folder}",
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
                f"      preflight create {inspection.folder} --force",
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
        "  manifest      valid",
        f"  package id    {package.package_id}",
        f"  plugin        {plugin.name} {plugin.module_version}  (id: {plugin.plugin_id})",
        f"  tier          {package.visibility.value}, {package.release_ring.value} ring",
        f"  entrypoint    {package.entrypoint}",
    ]
    if inspection.entrypoint_file is not None:
        relative = inspection.entrypoint_file.relative_to(inspection.folder.parent)
        lines.append(f"                -> {relative}  (inside this folder)")
        # The file really is there, so the line above is true -- but for a name
        # the interpreter already owns it is not the file that would be imported,
        # and a reader who stops here would take the report for a clean one.
        if inspection.unreachable_name is not None:
            lines.append(
                "                XX but not reachable by that name -- see below"
            )
        if inspection.missing_attribute is not None:
            lines.append(
                "                XX the named attribute is not in that file -- see below"
            )
    else:
        lines.append(f"                XX {inspection.problem}")

    if inspection.adapts_the_module:
        # A bare entrypoint is not a defect and must not be marked as one. It is
        # a check the reader is choosing to go without, and the one thing on this
        # screen that a package cannot be judged on -- so it is said plainly here
        # rather than left to be inferred from a missing colon.
        lines.append(
            "                adapted by preflight; this package does not report "
            "its own manifest"
        )

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

    if other_refusals:
        count = len(other_refusals)
        lines += [
            "",
            f"  {count} reason{'' if count == 1 else 's'} a host would refuse this "
            f"before importing it:",
        ]
        # A reason may run to several lines: the gate's refusal for a name the
        # interpreter owns carries its diagnosis on a second one. Every line sits
        # under the same column, or the second reads as a reason of its own --
        # the same rule `LoadReport.text` applies to the same strings.
        for reason in other_refusals:
            first, *rest = reason.splitlines() or [""]
            lines.append(f"    X {first}")
            lines += [f"      {line}".rstrip() for line in rest]

    late_refusals = inspection.late_refusals()
    if late_refusals:
        count = len(late_refusals)
        lines += [
            "",
            f"  {count} reason{'' if count == 1 else 's'} a host would refuse this "
            f"AFTER importing it:",
        ]
        # Same `X` as the block above. `!` is taken: in the tool list it marks a
        # risk worth a second look, which is the opposite of a decision. Both of
        # these are decisions, and the heading is what separates them.
        for reason in late_refusals:
            first, *rest = reason.splitlines() or [""]
            lines.append(f"    X {first}")
            lines += [f"      {line}".rstrip() for line in rest]

    lines.append("")
    if not inspection.consistent:
        lines.append(
            "  This package would be refused. Its code would never be imported."
        )
    elif late_refusals:
        # Said before the pre-import reasons, if there are any, because it is the
        # worse outcome: the refusals above cost the package nothing, and this
        # one costs it everything it does at import time.
        lines += [
            "  This package would be refused, and not before it had run --",
            "  the reason above is one only an import can discover.",
        ]
    elif refused_tools or other_refusals:
        # The two are worth distinguishing. A refused risk is the reader's own
        # rule coming back at them; a platform or a tier is the package being
        # wrong for this build no matter what the reader thinks about risk.
        whose = (
            "by your rule, not by preflight's."
            if refused_tools and not other_refusals
            else "by the rules any host applies before importing."
        )
        lines += [
            "  Paperwork is consistent, and this package would still be refused --",
            f"  {whose} Its code would never be imported.",
        ]
    else:
        lines += [
            "  Paperwork is consistent. preflight did not run this code and cannot",
            "  tell you whether it does what it says.",
        ]
    return "\n".join(lines)
