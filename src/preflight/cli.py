"""``preflight`` on the command line.

Three commands, and the important one is the first::

    preflight check  ./some-plugin     # read its paperwork. Executes nothing.
    preflight create ./some-plugin     # write down what you will permit it to do
    preflight demo                     # watch three plugins get refused

``check`` is the command you run on something you downloaded and have not read.
It is safe to point at untrusted code because it never imports it -- see
:mod:`preflight.inspect`. It is *not* a malware scanner, does not read the
package's code, and cannot tell you whether a package does what it says. It
tells you what the package **claims**, and whether those claims are coherent.

``--refuse`` on ``check`` and ``demo`` is not a fourth thing preflight knows how
to do. It is ``Policy(refuse_tool_risks=...)`` -- the gate that runs inside a
host at every startup -- asked at a terminal, so the exit code answers to the
host's rules rather than to preflight's defaults.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from preflight import __version__
from preflight.inspect import MANIFEST_NAME, format_inspection, inspect_directory
from preflight.manifest import ToolRisk

_NOT_IDENTIFIER = re.compile(r"[^0-9a-zA-Z_]+")


def _tool_risks(value: str) -> frozenset[ToolRisk]:
    """Parse one ``--refuse`` value: a comma-separated list of risk names.

    Raising ``ArgumentTypeError`` hands the failure to argparse, which reports
    it and exits ``2`` -- the same code the rest of this module uses for "you
    pointed me at something I cannot work with".
    """
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names:
        raise argparse.ArgumentTypeError("expected at least one risk name")
    risks = set()
    for name in names:
        try:
            risks.add(ToolRisk(name.lower()))
        except ValueError:
            valid = ", ".join(risk.value for risk in ToolRisk)
            raise argparse.ArgumentTypeError(
                f"unknown risk '{name}'. Valid risks: {valid}"
            ) from None
    return frozenset(risks)


def _refused_risks(args: argparse.Namespace) -> frozenset[ToolRisk]:
    """Every risk named across all occurrences of ``--refuse``."""
    return frozenset().union(*(getattr(args, "refuse", None) or [frozenset()]))


def _add_refuse_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--refuse",
        metavar="RISK[,RISK...]",
        type=_tool_risks,
        action="append",
        help=(
            "declared tool risks you will not accept. Repeatable. This is your "
            "rule, not preflight's -- the same one a host writes as "
            "Policy(refuse_tool_risks=...). Valid: "
            + ", ".join(risk.value for risk in ToolRisk)
        ),
    )


def _slug(name: str) -> str:
    """A folder name turned into something a Python module could be called."""
    cleaned = _NOT_IDENTIFIER.sub("_", name).strip("_").lower()
    return cleaned or "plugin"


def _guess_entrypoint(folder: Path) -> str:
    """Propose an entrypoint from what is on disk. ``check`` verifies it after."""
    module = _slug(folder.name)
    if (folder / "__init__.py").is_file():
        if (folder / "plugin.py").is_file():
            return f"{module}.plugin:create_plugin"
        return f"{module}:create_plugin"
    return f"{module}.plugin:create_plugin"


def _check(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.is_dir():
        print(f"preflight: '{target}' is not a directory", file=sys.stderr)
        return 2

    refuse = _refused_risks(args)
    inspections = inspect_directory(target)
    for index, inspection in enumerate(inspections):
        if index:
            print()
        print(format_inspection(inspection, refuse_tool_risks=refuse))

    # Both conditions mean the same thing -- this would not load -- so both are
    # exit 1. Incoherent paperwork and a risk the caller refused are different
    # reasons for one answer, and a script acting on the answer needs one code.
    would_load = all(
        item.consistent and not item.refused_tools(refuse) for item in inspections
    )
    return 0 if would_load else 1


def _create(args: argparse.Namespace) -> int:
    # Resolved, because everything below is derived from the folder's *name* --
    # the slug, the guessed entrypoint, the rename advice. `Path('.').name` is
    # the empty string, so `preflight create .` from inside the package, which
    # is the obvious way to run this, would otherwise be told that '' cannot be
    # a Python package name. `check` resolves for the same reason.
    folder = Path(args.path).resolve()
    if not folder.is_dir():
        print(f"preflight: '{folder}' is not a directory", file=sys.stderr)
        return 2

    destination = folder / MANIFEST_NAME
    if destination.exists() and not args.force:
        print(
            f"preflight: {destination} already exists. Pass --force to overwrite it.",
            file=sys.stderr,
        )
        return 2

    slug = _slug(folder.name)
    # A folder whose name is not a Python identifier can never be imported, and
    # no manifest can fix that. Say so instead of writing a file that looks like
    # progress and resolves to nothing.
    if slug != folder.name and not args.entrypoint:
        print(
            f"preflight: '{folder.name}' cannot be a Python package name, so nothing\n"
            f"inside it can be reached by an entrypoint. No manifest fixes this.\n"
            f"\n"
            f"Rename the folder first:\n"
            f"    {folder.name}  ->  {slug}\n"
            f"\n"
            f"Or pass --entrypoint if the module lives somewhere else.",
            file=sys.stderr,
        )
        return 2

    manifest = {
        "schema_version": "1.0",
        "package_id": args.package_id or f"local.{slug}",
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": args.entrypoint or _guess_entrypoint(folder),
        "plugin": {
            "schema_version": "1.0",
            "plugin_id": slug,
            "name": folder.name,
            "module_version": "0.1.0",
            "tools": [],
        },
    }
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {destination}")
    print()
    print("  This manifest records what you PERMIT this package to do. preflight")
    print("  did not read its code and has not checked whether the two agree.")
    print("  An empty `tools` list means it may expose none.")
    print()
    print("  Next:")
    print(f"      preflight check {folder}")
    return 0


def _example_plugins() -> Path | None:
    """The bundled example packages, wherever this copy of preflight was installed from.

    A wheel carries them at ``preflight/_examples``; a source checkout keeps
    them at the repository root, which is also where an editable install finds
    them. Neither location depends on the working directory, so ``demo`` runs
    the same from anywhere.
    """
    here = Path(__file__).resolve().parent
    candidates = (
        here / "_examples" / "plugins",
        here.parent.parent / "examples" / "plugins",
    )
    return next((path for path in candidates if path.is_dir()), None)


def _demo(args: argparse.Namespace) -> int:
    """Run the five bundled example plugins. Three of them deserve refusing."""
    examples = _example_plugins()
    if examples is None:
        print(
            "preflight: this build carries no example packages. Clone the\n"
            "repository and run `preflight demo` from inside it.",
            file=sys.stderr,
        )
        return 2

    from preflight.load import Policy, load_plugins

    refuse = _refused_risks(args)
    sys.path.insert(0, str(examples))
    result = load_plugins(
        examples,
        allow=[
            "example.greeter",
            "example.trespasser",
            "example.collider",
            "example.impostor",
            "example.janitor",
        ],
        policy=Policy(refuse_tool_risks=refuse),
    )
    print()
    print(result)
    print()

    ran = sum(1 for outcome in result.outcomes if outcome.code_ran)
    refused = result.refused
    inert = sum(1 for outcome in refused if not outcome.code_ran)
    print(f"  The {ran} lines above reading `top-level plugin code is executing` are")
    print(
        f"  tripwires: the first statement in a plugin package. "
        f"{inert} of the {len(refused)} refused"
    )
    print("  plugins never printed one, because they never got an import.")

    if ToolRisk.DESTRUCTIVE in refuse:
        print()
        print("  Two of those refusals are worth comparing. janitor declared its")
        print("  destructive tool in its manifest, so --refuse stopped it while it")
        print("  was still inert on disk. impostor declares two read-only tools and")
        print("  produces a destructive third one only once loaded, where no")
        print("  declaration-based gate can see it -- it was caught afterwards, by")
        print("  comparing what it reported against what it had declared.")
        print()
        print("  preflight enforces declarations. It does not detect concealment.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Decide whether a plugin may load from its manifest alone, "
            "before any of its code runs."
        ),
        epilog=(
            "These commands are for the moment you adopt a package you did not\n"
            "write. They are not the product, and running one protects nothing\n"
            "later -- none of this is running when your application is.\n"
            "\n"
            "The gate itself goes inside your program and runs at every startup:\n"
            "\n"
            "    from preflight import load_plugins\n"
            "    result = load_plugins('plugins', allow=['acme.weather'])\n"
            "\n"
            "Packages in that folder but missing from allow are never imported."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"preflight {__version__}",
        help="print the installed version and exit",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser(
        "check",
        help="read a package's manifest and declared tools. Executes nothing.",
        description=(
            "Reads the manifest, resolves the entrypoint against the filesystem, "
            "and lists every tool the package claims. Nothing is imported, so this "
            "is safe to run on code you have not read. It cannot tell you whether "
            "the package does what it says. With --refuse it exits non-zero on a "
            "package your host would turn away, which suits a pre-commit hook."
        ),
    )
    check.add_argument("path", help="a plugin package, or a folder of them")
    _add_refuse_flag(check)
    check.set_defaults(handler=_check)

    create = commands.add_parser(
        "create",
        help="write a manifest for a package that has none",
        description=(
            "Writes a manifest.json recording what you permit this package to do. "
            "preflight does not read the package's code to fill it in."
        ),
    )
    create.add_argument("path", help="the plugin package directory")
    create.add_argument("--entrypoint", help="module:attribute to call, e.g. pkg.plugin:build")
    create.add_argument("--package-id", help="dotted package id, e.g. acme.weather")
    create.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    create.set_defaults(handler=_create)

    demo = commands.add_parser(
        "demo",
        help="load five example plugins; three of them get refused",
        description=(
            "Loads the bundled examples through the real gate. Pass "
            "--refuse destructive to watch a fourth one get refused for a tool "
            "it declared honestly -- and to see the one that lied slip past the "
            "flag entirely, because it never declared anything."
        ),
    )
    _add_refuse_flag(demo)
    demo.set_defaults(handler=_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
